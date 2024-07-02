// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0

import { R2HTTPMetadata, R2ListOptions } from '@cloudflare/workers-types/2023-07-01';
import { Context } from './context';
import { b64Tou8, u8ToB64 } from './utils/base64';
import { PRIVATE_TOKEN_ISSUER_DIRECTORY } from '@cloudflare/privacypass-ts';

export const FAKE_DOMAIN_CACHE = 'cache.local';

export const getDirectoryCache = async (): Promise<Cache> => {
	return caches.open('response/issuer-directory');
};

export const DIRECTORY_CACHE_REQUEST = new Request(
	`https://${FAKE_DOMAIN_CACHE}${PRIVATE_TOKEN_ISSUER_DIRECTORY}`
);

export const clearDirectoryCache = async (): Promise<boolean> => {
	const cache = await getDirectoryCache();
	return cache.delete(DIRECTORY_CACHE_REQUEST);
};

export type CacheElement<T> = { value: T; expiration: Date };

interface ReadableCache {
	read<T>(key: string, setValFn: (key: string) => Promise<CacheElement<T>>): Promise<T>;
}

// This serialization is primitive, and can be optimized further if need be.
const serialize = <T>(value: T): string => {
	return JSON.stringify(value, (_key, value) => {
		if (value instanceof Uint8Array) {
			return `u8-${u8ToB64(value)}`;
		}
		if (value instanceof Date) {
			return `date-${value.toJSON()}`;
		}
		if (typeof value === 'string') {
			if (value.startsWith('u8-') || value.startsWith('date-')) {
				throw new Error('serialization error');
			}
		}
		return value;
	});
};

const deserialize = <T>(value: string): T => {
	return JSON.parse(value, (_key, value) => {
		if (value.startsWith && value.startsWith('u8-')) {
			return b64Tou8(value.slice('u8-'.length));
		}
		if (value.startsWith && value.startsWith('date-')) {
			return new Date(value.slice('date-'.length));
		}
		return value;
	});
};

export class InMemoryCache implements ReadableCache {
	private store: Map<string, CacheElement<string>>;

	constructor() {
		this.store = new Map();
	}

	async read<T>(key: string, setValFn: (key: string) => Promise<CacheElement<T>>): Promise<T> {
		const cachedValue = this.store.get(key);
		if (cachedValue !== undefined) {
			if (cachedValue.expiration > new Date()) {
				return deserialize(cachedValue.value);
			}
			this.store.delete(key);
		}
		const val = await setValFn(key);
		const newCacheValue = { value: serialize(val.value), expiration: val.expiration };
		this.store.set(key, newCacheValue);
		return val.value;
	}
}

export class APICache implements ReadableCache {
	constructor(private cacheKey: string) {}

	async read<T>(key: string, setValFn: (key: string) => Promise<CacheElement<T>>): Promise<T> {
		const cache = await caches.open(this.cacheKey);
		const request = new Request(`https://${FAKE_DOMAIN_CACHE}/${key}`);
		const cachedValue = await cache.match(request);
		if (cachedValue !== undefined) {
			const val = await cachedValue.text();
			return deserialize(val);
		}
		const val = await setValFn(key);
		await cache.put(
			request,
			new Response(serialize(val.value), {
				headers: { expires: val.expiration.toUTCString() },
			})
		);
		return val.value;
	}
}

// CascadingCache reads from the first cache, failing back to the second cache
// on cache miss, and so on. A ReadableCache implementation is supposed to cache
// results from later caches to avoid future cache misses.
export class CascadingCache implements ReadableCache {
	private caches: ReadableCache[];
	constructor(...caches: ReadableCache[]) {
		this.caches = caches;
	}

	async read<T>(key: string, setValFn: (key: string) => Promise<CacheElement<T>>): Promise<T> {
		const caches = this.caches;
		const setValFnBuilder = (i: number): ((key: string) => Promise<CacheElement<T>>) => {
			if (i >= caches.length) {
				return setValFn;
			}
			return async (key: string) => ({
				value: await caches[i].read(key, setValFnBuilder(i + 1)),
				expiration: new Date(), // TODO: find a way to use setVal expiration instead
			});
		};
		const cachedValue = await setValFnBuilder(0)(key);
		return cachedValue.value;
	}
}

export const DEFAULT_R2_BUCKET_CACHE_TTL_IN_MS = 5 * 60 * 1000;

export class CachedR2Object {
	public checksums: R2Checksums;
	public customMetadata?: Record<string, string>;
	public etag: string;
	public httpEtag: string;
	public httpMetadata?: R2HTTPMetadata;
	public key: string;
	public size: number;
	public uploaded: Date;
	public version: string;

	constructor(
		object: R2Object,
		public data?: Uint8Array
	) {
		this.checksums = object.checksums;
		this.customMetadata = object.customMetadata;
		this.etag = object.etag;
		this.httpEtag = object.httpEtag;
		this.httpMetadata = object.httpMetadata;
		this.key = object.key;
		this.size = object.size;
		this.uploaded = object.uploaded;
		this.version = object.version;
	}
}

export class CachedR2Objects {
	public delimitedPrefixes: string[];
	public objects: CachedR2Object[];
	public truncated: boolean;

	constructor(objects: R2Objects) {
		this.delimitedPrefixes = objects.delimitedPrefixes;
		this.objects = objects.objects.map(o => new CachedR2Object(o));
		this.truncated = objects.truncated;
	}
}

const R2Method = {
	GET: 'get',
	HEAD: 'head',
	LIST: 'list',
};
const R2MethodSet = new Set(Object.values(R2Method));

export class CachedR2Bucket {
	private bucket: R2Bucket;
	constructor(
		private ctx: Context,
		bucket: R2Bucket,
		private cache: ReadableCache,
		private ttl_in_ms = DEFAULT_R2_BUCKET_CACHE_TTL_IN_MS
	) {
		this.bucket = new Proxy(bucket, {
			get: (target, prop, receiver) => {
				const method = Reflect.get(target, prop, receiver);
				if (R2MethodSet.has(prop.toString())) {
					const startTime = ctx.performance.now();
					return async function (...args: unknown[]) {
						try {
							return await Reflect.apply(method, target, args);
						} finally {
							const duration = ctx.performance.now() - startTime;
							ctx.metrics.r2RequestsDurationMs.observe(duration, { method: prop.toString() });
						}
					};
				}
				return method;
			},
		});
	}

	// WARNING: key should be lowered than 1024 bytes
	// See https://developers.cloudflare.com/r2/reference/limits/
	head(key: string): Promise<CachedR2Object | null> {
		const cacheKey = `head/${key}`;
		return this.cache.read(cacheKey, async () => {
			const object = await this.bucket.head(key);
			if (object === null) {
				return { value: null, expiration: new Date() };
			}
			const value = new CachedR2Object(object);
			return {
				value,
				expiration: new Date(Date.now() + this.ttl_in_ms),
			};
		});
	}

	list(options?: R2ListOptions | undefined): Promise<CachedR2Objects> {
		const cacheKey = `list/${JSON.stringify(options)}`;
		return this.cache.read(cacheKey, async () => {
			const objects = await this.bucket.list(options);
			const value = new CachedR2Objects(objects);
			return {
				value,
				expiration: new Date(Date.now() + this.ttl_in_ms),
			};
		});
	}

	// WARNING: key should be lowered than 1024 bytes
	// See https://developers.cloudflare.com/r2/reference/limits/
	async get(key: string, options?: R2GetOptions): Promise<CachedR2Object | null> {
		const cacheKey = `get/${key}`;
		return this.cache.read(cacheKey, async () => {
			const object = await this.bucket.get(key, options);
			if (object === null) {
				return { value: null, expiration: new Date() };
			}
			const value = new CachedR2Object(object, new Uint8Array(await object.arrayBuffer()));
			return {
				value,
				expiration: new Date(Date.now() + this.ttl_in_ms),
			};
		});
	}
}
