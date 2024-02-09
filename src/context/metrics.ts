import { CounterType, RegistryType } from 'promjs';
import { Registry } from 'promjs/registry';
export const METRICS_ENDPOINT = 'https://workers-logging.cfdata.org/prometheus';

export interface RegistryOptions {
	bearerToken?: string;
}

/**
 * A wrapper around the promjs registry to manage registering and publishing metrics
 */
export class MetricsRegistry {
	registry: RegistryType;
	options: RegistryOptions;

	requestsTotal: CounterType;
	erroredRequestsTotal: CounterType;
	keyRotationTotal: CounterType;
	keyClearTotal: CounterType;
	issuanceRequestTotal: CounterType;
	signedTokenTotal: CounterType;
	directoryCacheMissTotal: CounterType;

	constructor(options: RegistryOptions) {
		this.options = options;
		this.registry = new Registry();

		this.requestsTotal = this.registry.create('counter', 'requests_total', 'total requests');
		this.erroredRequestsTotal = this.registry.create(
			'counter',
			'errored_requests_total',
			'Errored requests served to eyeball'
		);
		this.keyRotationTotal = this.registry.create(
			'counter',
			'key_rotation_total',
			'Number of key rotation performed.'
		);
		this.keyClearTotal = this.registry.create(
			'counter',
			'key_clear_total',
			'Number of key clear performed.'
		);
		this.issuanceRequestTotal = this.registry.create(
			'counter',
			'issuance_request_total',
			'Number of requests for private token issuance.'
		);
		this.signedTokenTotal = this.registry.create(
			'counter',
			'signed_token_total',
			'Number of issued signed private tokens.'
		);
		this.directoryCacheMissTotal = this.registry.create(
			'counter',
			'directory_cache_miss_total',
			'Number of requests for private token issuer directory which are not served by the cache.'
		);
	}

	/**
	 * Publishes metrics to the workers metrics API
	 * This function is a no-op in test and wrangler environements
	 */
	async publish(): Promise<void> {
		await fetch(METRICS_ENDPOINT, {
			method: 'POST',
			headers: {
				Authorization: `Bearer ${this.options.bearerToken}`,
			},
			body: this.registry.metrics(),
		});
	}
}
