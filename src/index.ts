// Copyright (c) 2023 Cloudflare, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Bindings } from './bindings';
import { Context } from './context';
import { Router } from './router';
import { HeaderNotDefinedError, InternalCacheError } from './errors';
import { IssuerConfigurationResponse, TokenType } from './types';
import { b64ToB64URL, b64Tou8, b64URLtoB64, u8ToB64 } from './utils/base64';
import {
	MediaType,
	PRIVATE_TOKEN_ISSUER_DIRECTORY,
	TOKEN_TYPES,
	publicVerif,
	util,
} from '@cloudflare/privacypass-ts';
import { ConsoleLogger } from './context/logging';
import { KeyError, MetricsRegistry } from './context/metrics';
import { hexEncode } from './utils/hex';
import { DIRECTORY_CACHE_REQUEST, clearDirectoryCache, getDirectoryCache } from './cache';
const { BlindRSAMode, Issuer, TokenRequest } = publicVerif;

const keyToTokenKeyID = async (key: Uint8Array): Promise<number> => {
	const hash = await crypto.subtle.digest('SHA-256', key);
	const u8 = new Uint8Array(hash);
	return u8[u8.length - 1];
};

interface StorageMetadata extends Record<string, string> {
	version: string;
	publicKey: string;
	tokenKeyID: string;
}

export const handleTokenRequest = async (ctx: Context, request: Request) => {
	ctx.metrics.issuanceRequestTotal.inc();
	const contentType = request.headers.get('content-type');
	if (!contentType || contentType !== MediaType.PRIVATE_TOKEN_REQUEST) {
		throw new HeaderNotDefinedError(`"Content-Type" must be "${MediaType.PRIVATE_TOKEN_REQUEST}"`);
	}

	const buffer = await request.arrayBuffer();
	const tokenRequest = TokenRequest.deserialize(new Uint8Array(buffer));

	if (tokenRequest.tokenType !== TOKEN_TYPES.BLIND_RSA.value) {
		throw new Error('Invalid token type');
	}

	const keyID = tokenRequest.truncatedTokenKeyId.toString();
	const key = await ctx.cache.ISSUANCE_KEYS.get(keyID);

	if (key === null) {
		ctx.metrics.issuanceKeyErrorTotal.inc({ key_id: keyID, type: KeyError.NOT_FOUND });
		throw new Error('No key found for the requested key id');
	}

	const privateKey = key.data;
	if (privateKey === undefined) {
		ctx.metrics.issuanceKeyErrorTotal.inc({ key_id: keyID, type: KeyError.MISSING_PRIVATE_KEY });
		throw new Error('No private key found for the requested key id');
	}
	let sk: CryptoKey;
	try {
		sk = await crypto.subtle.importKey(
			'pkcs8',
			privateKey,
			{
				name: ctx.isTest() ? 'RSA-PSS' : 'RSA-RAW',
				hash: 'SHA-384',
				length: 2048,
			},
			true,
			['sign']
		);
	} catch (e) {
		ctx.metrics.issuanceKeyErrorTotal.inc({ key_id: keyID, type: KeyError.INVALID_PRIVATE_KEY });
		throw e;
	}
	const pkEnc = key?.customMetadata?.publicKey;
	if (!pkEnc) {
		ctx.metrics.issuanceKeyErrorTotal.inc({ key_id: keyID, type: KeyError.MISSING_PUBLIC_KEY });
		throw new Error('No public key found for the requested key id');
	}
	const pk = await crypto.subtle.importKey(
		'spki',
		util.convertRSASSAPSSToEnc(b64Tou8(b64URLtoB64(pkEnc))),
		{ name: 'RSA-PSS', hash: 'SHA-384' },
		true,
		['verify']
	);

	const domain = new URL(request.url).host;
	const issuer = new Issuer(BlindRSAMode.PSS, domain, sk, pk, { supportsRSARAW: true });
	const signedToken = await issuer.issue(tokenRequest);
	ctx.metrics.signedTokenTotal.inc({ key_id: keyID });

	return new Response(signedToken.serialize(), {
		headers: { 'content-type': MediaType.PRIVATE_TOKEN_RESPONSE },
	});
};

export const handleHeadTokenDirectory = async (ctx: Context, request: Request) => {
	const getResponse = await handleTokenDirectory(ctx, request);

	return new Response(undefined, {
		status: getResponse.status,
		headers: getResponse.headers,
	});
};

export const handleTokenDirectory = async (ctx: Context, request: Request) => {
	const cache = await getDirectoryCache();
	let cachedResponse: Response | undefined;
	try {
		cachedResponse = await cache.match(DIRECTORY_CACHE_REQUEST);
	} catch (e: unknown) {
		const err = e as Error;
		throw new InternalCacheError(err.message);
	}
	if (cachedResponse) {
		if (request.headers.get('if-none-match') === cachedResponse.headers.get('etag')) {
			return new Response(undefined, {
				status: 304,
				headers: cachedResponse.headers,
			});
		}
		return cachedResponse;
	}
	ctx.metrics.directoryCacheMissTotal.inc();

	const keys = await ctx.cache.ISSUANCE_KEYS.list({ include: ['customMetadata'] });

	if (keys.objects.length === 0) {
		throw new Error('Issuer not initialised');
	}

	const directory: IssuerConfigurationResponse = {
		'issuer-request-uri': '/token-request',
		'token-keys': keys.objects.map(key => ({
			'token-type': TokenType.BlindRSA,
			'token-key': (key.customMetadata as StorageMetadata).publicKey,
			'not-before': new Date(key.uploaded).getTime(),
		})),
	};

	const body = JSON.stringify(directory);
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
	);
	const etag = `"${hexEncode(digest)}"`;

	const response = new Response(body, {
		headers: {
			'content-type': MediaType.PRIVATE_TOKEN_ISSUER_DIRECTORY,
			'cache-control': `public, max-age=${ctx.env.DIRECTORY_CACHE_MAX_AGE_SECONDS}`,
			'content-length': body.length.toString(),
			'date': new Date().toUTCString(),
			etag,
		},
	});
	ctx.waitUntil(cache.put(DIRECTORY_CACHE_REQUEST, response.clone()));

	return response;
};

export const handleRotateKey = async (ctx: Context, _request?: Request) => {
	ctx.metrics.keyRotationTotal.inc();

	// Generate a new type 2 Issuer key
	let publicKeyEnc: string;
	let tokenKeyID: number;
	let privateKey: ArrayBuffer;
	do {
		const keypair = (await crypto.subtle.generateKey(
			{
				name: 'RSA-PSS',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: { name: 'SHA-384' },
			},
			true,
			['sign', 'verify']
		)) as CryptoKeyPair;
		const publicKey = new Uint8Array(
			(await crypto.subtle.exportKey('spki', keypair.publicKey)) as ArrayBuffer
		);
		const rsaSsaPssPublicKey = util.convertEncToRSASSAPSS(publicKey);
		publicKeyEnc = b64ToB64URL(u8ToB64(rsaSsaPssPublicKey));
		tokenKeyID = await keyToTokenKeyID(rsaSsaPssPublicKey);
		privateKey = (await crypto.subtle.exportKey('pkcs8', keypair.privateKey)) as ArrayBuffer;
		// The bellow condition ensure there is no collision between truncated_token_key_id provided by the issuer
		// This is a 1/256 with 2 keys, and 256/256 chances with 256 keys. This means an issuer cannot have more than 256 keys at the same time.
		// Otherwise, this loop is going to be infinite. With 255 keys, this iteration might take a while.
	} while ((await ctx.cache.ISSUANCE_KEYS.head(tokenKeyID.toString())) !== null);

	// check if it's the initialisation phase
	const latest = await ctx.env.ISSUANCE_KEYS.head('latest');
	const version = latest?.customMetadata?.version ?? '0';
	const next = Number.parseInt(version) + 1;

	const metadata: StorageMetadata = {
		version: next.toString(),
		publicKey: publicKeyEnc,
		tokenKeyID: tokenKeyID.toString(),
	};

	await ctx.env.ISSUANCE_KEYS.put(tokenKeyID.toString(), privateKey, {
		customMetadata: metadata,
	});

	ctx.waitUntil(clearDirectoryCache());

	return new Response(`New key ${publicKeyEnc}`, { status: 201 });
};

const handleClearKey = async (ctx: Context, _request?: Request) => {
	ctx.metrics.keyClearTotal.inc();
	const keys = await ctx.env.ISSUANCE_KEYS.list();

	let latestKey: R2Object = keys.objects[0];
	const toDelete: Set<string> = new Set();

	// only keep the latest key
	for (const key of keys.objects) {
		if (latestKey.uploaded < key.uploaded) {
			toDelete.add(latestKey.key);
			latestKey = key;
		} else if (key.uploaded !== latestKey.uploaded) {
			toDelete.add(key.key);
		}
	}
	const toDeleteArray = [...toDelete];
	await ctx.env.ISSUANCE_KEYS.delete(toDeleteArray);

	ctx.waitUntil(clearDirectoryCache());

	return new Response(`Keys cleared: ${toDeleteArray.join('\n')}`, { status: 201 });
};

export default {
	async fetch(request: Request, env: Bindings, ctx: ExecutionContext) {
		// router defines all API endpoints
		// this ease testing, as test can be performed on specific handler methods, not necessardily e2e
		const router = new Router();

		router
			.get(PRIVATE_TOKEN_ISSUER_DIRECTORY, handleTokenDirectory)
			.post('/token-request', handleTokenRequest)
			.post('/admin/rotate', handleRotateKey)
			.post('/admin/clear', handleClearKey);

		return router.handle(
			request as Request<Bindings, IncomingRequestCfProperties<unknown>>,
			env,
			ctx
		);
	},

	async scheduled(event: ScheduledEvent, env: Bindings, ectx: ExecutionContext) {
		const ctx = new Context(
			env,
			ectx.waitUntil.bind(ectx),
			new ConsoleLogger(),
			new MetricsRegistry(env, { bearerToken: env.LOGGING_SHIM_TOKEN })
		);
		const date = new Date(event.scheduledTime);
		const isRotation = date.getUTCDate() === 1;

		if (isRotation) {
			await handleRotateKey(ctx);
		} else {
			await handleClearKey(ctx);
		}
	},
};
