import type {
	// - for override
	AuthenticationExtensionsClientInputs as TypeScriptAuthenticationExtensionsClientInputs,
	AuthenticatorTransportFuture as AuthenticatorTransportFutureBase,
	PublicKeyCredentialDescriptorJSON as PublicKeyCredentialDescriptorJSONBase,
	AuthenticatorAttestationResponseJSON as AuthenticatorAttestationResponseJSONBase,
	// - for use & reexport
	Base64URLString,
	PublicKeyCredentialJSON,
	PublicKeyCredentialUserEntityJSON,
} from "@simplewebauthn/typescript-types";
import { z, type ZodType } from "zod";

export type {
	AttestationConveyancePreference,
	AuthenticationCredential,
	AuthenticatorAssertionResponse,
	AuthenticatorAttachment,
	AuthenticatorAttestationResponse,
	AuthenticatorSelectionCriteria,
	AuthenticatorTransport,
	COSEAlgorithmIdentifier,
	Crypto,
	PublicKeyCredentialCreationOptions,
	PublicKeyCredentialDescriptor,
	PublicKeyCredentialParameters,
	PublicKeyCredentialRequestOptions,
	PublicKeyCredentialRpEntity,
	PublicKeyCredentialType,
	PublicKeyCredentialUserEntity,
	RegistrationCredential,
	UserVerificationRequirement,
} from "@simplewebauthn/typescript-types";

export type {
	Base64URLString,
	PublicKeyCredentialJSON,
	PublicKeyCredentialUserEntityJSON,
};

import base64 from '@hexagon/base64';
const base64UrlSchema: ZodType<Base64URLString> = z.string().refine((value) => {
	const returnVal = !!base64.base64.validate(value, true)
	console.log('base64UrlSchema', value, returnVal)
	return returnVal
}, { message: "Invalid base64url" });

export interface PublicKeyCredentialDescriptorJSON extends Omit<PublicKeyCredentialDescriptorJSONBase, "transports"> {
	transports?: AuthenticatorTransportFuture[];
};

export type AuthenticatorTransportFuture =  'bt' | AuthenticatorTransportFutureBase | (string & {}); // The type (string & {}) allows any string while still giving autocomplete and type-on-hover hints


export const publicKeyCredentialDescriptorJSONSchema: ZodType<PublicKeyCredentialDescriptorJSON> = z.object({
    id: base64UrlSchema,
    type: z.literal("public-key"),
    transports: z.array(z.string()).optional(),
});


export interface PublicKeyCredentialUserEntityWithIcon extends PublicKeyCredentialUserEntityJSON {
    icon?: string;
}

export const publicKeyCredentialUserEntityWithIconSchema: ZodType<PublicKeyCredentialUserEntityWithIcon> = z.object({
	id: base64UrlSchema,
	name: z.string(),
	displayName: z.string(),
	icon: z.string().optional(),
});

export interface PublicKeyCredentialRpEntityWithIcon extends PublicKeyCredentialRpEntity {
	icon?: string;
}

export const publicKeyCredentialRpEntityWithIconSchema: ZodType<PublicKeyCredentialRpEntityWithIcon> = z.object({
	id: z.string(), // So, funny story. I initially had this as base64UrlSchema and spent, like, 20 minutes debugging, finally found it
	name: z.string(),
	icon: z.string().optional(),
});

export interface AuthenticationExtensionsPRFValues {
    first: BufferSource;
    second?: BufferSource;
};

export const arrayBufferViewSchema: ZodType<ArrayBufferView> = z.object({
    buffer: z.instanceof(ArrayBuffer),
    byteLength: z.number(),
    byteOffset: z.number(),
})

export const bufferSourceSchema: ZodType<BufferSource> = z.union([z.instanceof(ArrayBuffer), arrayBufferViewSchema]);

export const authenticationExtensionsPRFValuesSchema: ZodType<AuthenticationExtensionsPRFValues> = z.object({
	first: bufferSourceSchema,
	second: bufferSourceSchema.optional(),
});

export interface AuthenticationExtensionsPRFInputs {
    eval?: AuthenticationExtensionsPRFValues;
    evalByCredential?: Record<string, AuthenticationExtensionsPRFValues>;
};

export const authenticationExtensionsPRFInputsSchema: ZodType<AuthenticationExtensionsPRFInputs> = z.object({
	eval: authenticationExtensionsPRFValuesSchema.optional(),
	evalByCredential: z.record(authenticationExtensionsPRFValuesSchema).optional(),
});

export interface AuthenticationExtensionsSupplementalPubKeysInputs {
    scopes: string[];
	/** @default "indirect" */
    attestation?: string;
	/** @default [] */
    attestationFormats?: string[];
};

export const authenticationExtensionsSupplementalPubKeysInputsSchema: ZodType<AuthenticationExtensionsSupplementalPubKeysInputs> = z.object({
	scopes: z.array(z.string()),
	attestation: z.string().optional(),
	attestationFormats: z.array(z.string()).optional(),
});



export type LargeBlobSupport = "preferred" | "required";

export const largeBlobSupportSchema: ZodType<LargeBlobSupport> = z.union([
	z.literal("preferred"),
	z.literal("required"),
]);

/**
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationextensionslargeblobinputs
 */
export interface AuthenticationExtensionsLargeBlobInputs {
	// - Only valid during registration.
	support?: LargeBlobSupport;

	// - A boolean that indicates that the Relying Party would like to fetch the previously-written blob associated with the asserted credential. Only valid during authentication.
	read?: boolean;

	// - An opaque byte string that the Relying Party wishes to store with the existing credential. Only valid during authentication.
	// - We impose that the data is passed as base64-url encoding to make better align the passing of data from RN to native code
	write?: Base64URLString;
}

export const authenticationExtensionsLargeBlobInputsSchema: ZodType<AuthenticationExtensionsLargeBlobInputs> = z.object({
	support: largeBlobSupportSchema.optional(),
	read: z.boolean().optional(),
	write: z.string().optional(),
});


/**
 * TypeScript's types are behind the latest extensions spec, so we define them here.
 * Should eventually be replaced by TypeScript's when TypeScript gets updated to
 * know about it (sometime after ~~5.3~~ 5.5)
 *
 * This does not include any of the Android-specific extensions (which there are a good number of)
 * since, frankly, Android's docs on anything FIDO2 really, really, really suck.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationextensionsclientinputs
 */
export type AuthenticationExtensionsClientInputs = TypeScriptAuthenticationExtensionsClientInputs & {
	[key: string]: unknown;
	largeBlob?: AuthenticationExtensionsLargeBlobInputs;
	appidExclude?: string;
    prf?: AuthenticationExtensionsPRFInputs;
	supplementalPubKeys?: AuthenticationExtensionsSupplementalPubKeysInputs;
}

export const authenticationExtensionsClientInputsSchema: ZodType<AuthenticationExtensionsClientInputs> = z.union([z.record(z.string()), z.object({
	largeBlob: authenticationExtensionsLargeBlobInputsSchema.optional(),
	appidExclude: z.string().optional(),
	prf: authenticationExtensionsPRFInputsSchema.optional(),
	supplementalPubKeys: authenticationExtensionsSupplementalPubKeysInputsSchema.optional(),
})]);

// - Supplemental Public keys extension https://w3c.github.io/webauthn/#sctn-supplemental-public-keys-extension-definition
interface AuthenticationExtensionsSupplementalPubKeysOutputs {
	signatures: ArrayBuffer[];
};

export const authenticationExtensionsSupplementalPubKeysOutputsSchema: ZodType<AuthenticationExtensionsSupplementalPubKeysOutputs> = z.object({
	signatures: z.array(z.instanceof(ArrayBuffer)),
});

// - largeBlob extension: https://w3c.github.io/webauthn/#sctn-large-blob-extension
export interface AuthenticationExtensionsClientOutputs {
	[key: string]: unknown;
	supplementalPubKeys?: AuthenticationExtensionsSupplementalPubKeysOutputs;
	largeBlob?: Omit<AuthenticationExtensionsLargeBlobOutputsJson, "blob"> & {
		blob?: ArrayBuffer;
	};
}

export const authenticationExtensionsClientOutputsSchema: ZodType<AuthenticationExtensionsClientOutputs> = z.union([z.record(z.string()), z.object({
	supplementalPubKeys: authenticationExtensionsSupplementalPubKeysOutputsSchema.optional(),
	largeBlob: z.object({
		supported: z.boolean().optional(),
		written: z.boolean().optional(),
		blob: z.instanceof(ArrayBuffer).optional(),
	}).optional(),
})]);

/**
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationextensionslargebloboutputs
 */
export interface AuthenticationExtensionsLargeBlobOutputsJson {
	// - true if, and only if, the created credential supports storing large blobs. Only present in registration outputs.
	supported?: boolean;

	// - The opaque byte string that was associated with the credential identified by rawId. Only valid if read was true.
	blob?: Base64URLString;

	// - A boolean that indicates that the contents of write were successfully stored on the authenticator, associated with the specified credential.
	written?: boolean;
}

export const authenticationExtensionsLargeBlobOutputsSchema: ZodType<AuthenticationExtensionsLargeBlobOutputsJson> = z.object({
	supported: z.boolean().optional(),
	blob: base64UrlSchema.optional(),
	written: z.boolean().optional(),
});



// - largeBlob extension: https://w3c.github.io/webauthn/#sctn-large-blob-extension
export interface AuthenticationExtensionsClientOutputsJSON extends Omit<AuthenticationExtensionsClientOutputs, 'largeBlob'> {
	largeBlob?: AuthenticationExtensionsLargeBlobOutputsJson;
}

export const authenticationExtensionsClientOutputsJSONSchema: ZodType<AuthenticationExtensionsClientOutputsJSON> = z.object({
	largeBlob: authenticationExtensionsLargeBlobOutputsSchema.optional(),
});


/**
 * A variant of PublicKeyCredentialCreationOptions suitable for JSON transmission
 *
 * This should eventually get replaced with official TypeScript DOM types when WebAuthn L3 types
 * eventually make it into the language:
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-publickeycredentialcreationoptionsjson
 */
export interface PublicKeyCredentialCreationOptionsJSON {
	rp: PublicKeyCredentialRpEntityWithIcon;
	user: PublicKeyCredentialUserEntityWithIcon;
	challenge: Base64URLString;
	pubKeyCredParams: PublicKeyCredentialParameters[];
	timeout?: number;
	excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
	authenticatorSelection?: AuthenticatorSelectionCriteria;
	attestation?: AttestationConveyancePreference;
	extensions?: AuthenticationExtensionsClientInputs;
}

export const publicKeyCredentialCreationOptionsJSONSchema: ZodType<PublicKeyCredentialCreationOptionsJSON> = z.object({
	rp: publicKeyCredentialRpEntityWithIconSchema,
	user: publicKeyCredentialUserEntityWithIconSchema,
	challenge: base64UrlSchema,
	pubKeyCredParams: z.array(z.object({
		type: z.literal("public-key"),
		alg: z.number(),
	})),
	timeout: z.number().optional(),
	excludeCredentials: z.array(publicKeyCredentialDescriptorJSONSchema).optional(),
	authenticatorSelection: z.object({
		authenticatorAttachment: z.union([z.literal("cross-platform"), z.literal("platform")]).optional(),
		residentKey: z.union([z.literal("required"), z.literal("preferred"), z.literal("discouraged")]).optional(),
		requireResidentKey: z.boolean().optional(),
		userVerification: z.union([z.literal("required"), z.literal("preferred"), z.literal("discouraged")]).optional(),
		requireUserVerification: z.boolean().optional(),
	}).optional(),
	attestation: z.union([z.literal("none"), z.literal("indirect"), z.literal("direct"), z.literal("enterprise")]).optional(),
	extensions: authenticationExtensionsClientInputsSchema.optional(),
});


/**
 * A variant of PublicKeyCredentialRequestOptions suitable for JSON transmission
 */
export interface PublicKeyCredentialRequestOptionsJSON {
	challenge: Base64URLString;
	timeout?: number;
	rpId: string;
	allowCredentials?: PublicKeyCredentialDescriptorJSON[];
	userVerification?: UserVerificationRequirement;
	extensions?: AuthenticationExtensionsClientInputs;
}

export const publicKeyCredentialRequestOptionsJSONSchema: ZodType<PublicKeyCredentialRequestOptionsJSON> = z.object({
	challenge: base64UrlSchema,
	timeout: z.number().optional(),
	rpId: z.string(),
	allowCredentials: z.array(publicKeyCredentialDescriptorJSONSchema).optional(),
	userVerification: z.union([z.literal("required"), z.literal("preferred"), z.literal("discouraged")]).optional(),
	extensions: z.object({
		largeBlob: z.object({
			read: z.boolean().optional(),
		}).optional(),
	}).optional(),
});

export interface AuthenticatorAttestationResponseJSON extends Omit<AuthenticatorAttestationResponseJSONBase, "transports"> {
    transports?: AuthenticatorTransportFuture[];
}

export const authenticatorAttestationResponseJSONSchema: ZodType<AuthenticatorAttestationResponseJSON> = z.object({
	clientDataJSON: base64UrlSchema,
	attestationObject: base64UrlSchema,
	authenticatorData: base64UrlSchema,
	transports: z.array(z.string()).optional(),
	publicKeyAlgorithm: z.number().optional(),
	publicKey: base64UrlSchema.optional(),
});

/**
 * A slightly-modified RegistrationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded so that they can be sent as JSON.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-registrationresponsejson
 */
export interface RegistrationResponseJSON {
	id: Base64URLString;
	rawId: Base64URLString;
	response: AuthenticatorAttestationResponseJSON;
	authenticatorAttachment?: AuthenticatorAttachment;
	clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
	type: PublicKeyCredentialType;
}

export const registrationResponseJSONSchema: ZodType<RegistrationResponseJSON> = z.object({
	id: base64UrlSchema,
	rawId: base64UrlSchema,
	response: authenticatorAttestationResponseJSONSchema,
	authenticatorAttachment: z.union([z.literal("cross-platform"), z.literal("platform")]).optional(),
	clientExtensionResults: authenticationExtensionsClientOutputsJSONSchema,
	type: z.literal("public-key"),
});

/**
 * A slightly-modified AuthenticatorAssertionResponse to simplify working with ArrayBuffers that
 * are Base64URL-encoded so that they can be sent as JSON.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticatorassertionresponsejson
 */
export interface AuthenticatorAssertionResponseJSON {
	clientDataJSON: Base64URLString;
	authenticatorData: Base64URLString;
	signature: Base64URLString;
	userHandle?: string;
}

export const authenticatorAssertionResponseJSONSchema: ZodType<AuthenticatorAssertionResponseJSON> = z.object({
	clientDataJSON: base64UrlSchema,
	authenticatorData: base64UrlSchema,
	signature: base64UrlSchema,
	userHandle: z.string().optional(),
});

/**
 * A slightly-modified AuthenticationCredential to simplify working with ArrayBuffers that
 * are Base64URL-encoded so that they can be sent as JSON.
 *
 * - Specification reference: https://w3c.github.io/webauthn/#dictdef-authenticationresponsejson
 */
export interface AuthenticationResponseJSON {
	id: Base64URLString;
	rawId: Base64URLString;
	response: AuthenticatorAssertionResponseJSON;
	authenticatorAttachment?: AuthenticatorAttachment;
	clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
	type: PublicKeyCredentialType;
}

export const authenticationResponseJSONSchema: ZodType<AuthenticationResponseJSON> = z.object({
	id: base64UrlSchema,
	rawId: base64UrlSchema,
	response: authenticatorAssertionResponseJSONSchema,
	authenticatorAttachment: z.union([z.literal("cross-platform"), z.literal("platform")]).optional(),
	clientExtensionResults: authenticationExtensionsClientOutputsJSONSchema,
	type: z.literal("public-key"),
});
