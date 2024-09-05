import {
	registrationResponseJSONSchema,
	authenticationResponseJSONSchema,
	type AuthenticationExtensionsLargeBlobInputs,
	type AuthenticationResponseJSON,
	type PublicKeyCredentialCreationOptionsJSON,
	type PublicKeyCredentialRequestOptionsJSON,
	type RegistrationResponseJSON,
} from './ReactNativePasskeys.types'

import { WebAuthnError as SimpleWebAuthnError } from '@simplewebauthn/browser';

export * from './ReactNativePasskeys.types'
export * from './errors'

// Import the native module. On web, it will be resolved to ReactNativePasskeys.web.ts
// and on native platforms to ReactNativePasskeys.ts
import ReactNativePasskeysModule from './ReactNativePasskeysModule'
import { errorMessageToEnumValue, type WebAuthnError, type WebAuthnErrorInfo } from './errors';

export function isSupported(): boolean {
	return ReactNativePasskeysModule.isSupported()
}

export function isAutoFillAvailable(): boolean {
	return ReactNativePasskeysModule.isAutoFillAvailable()
}

export async function startRegistration(
	request: Omit<PublicKeyCredentialCreationOptionsJSON, 'extensions'> & {
		// - only largeBlob is supported currently on iOS
		// - no extensions are currently supported on Android
		extensions?: { largeBlob?: AuthenticationExtensionsLargeBlobInputs }
	} & Pick<CredentialCreationOptions, 'signal'>,
): Promise<RegistrationResponseJSON | WebAuthnErrorInfo> {
	let res: Awaited<ReturnType<typeof ReactNativePasskeysModule.startRegistration>>
	try {
		res =  await ReactNativePasskeysModule.startRegistration(request)
	} catch (e) {
		if (e instanceof Error) {
			if (e instanceof SimpleWebAuthnError) {
				return errorMessageToEnumValue(e.code, e, 'authentication')
			} else {
				return errorMessageToEnumValue(e.message, e, 'authentication')
			}
		}

		throw e;
	}


	if (typeof res === 'string') {
		return registrationResponseJSONSchema.parse(JSON.parse(res))
	} else {
		return registrationResponseJSONSchema.parse(res)
	}
}

export async function startAuthentication(
	request: Omit<PublicKeyCredentialRequestOptionsJSON, 'extensions'> & {
		// - only largeBlob is supported currently on iOS
		// - no extensions are currently supported on Android
		extensions?: { largeBlob?: AuthenticationExtensionsLargeBlobInputs }
	},
): Promise<AuthenticationResponseJSON | WebAuthnErrorInfo> {
	let res: Awaited<ReturnType<typeof ReactNativePasskeysModule.startAuthentication>>
	try {
		res = await ReactNativePasskeysModule.startAuthentication(request)
	} catch (e) {
		if (e instanceof Error) {
			if (e instanceof SimpleWebAuthnError) {
				return errorMessageToEnumValue(e.code, e, 'authentication')
			} else {
				return errorMessageToEnumValue(e.message, e, 'authentication')
			}
		}

		throw e;
	}


	if (typeof res === 'string') {
		return authenticationResponseJSONSchema.parse(JSON.parse(res))
	} else {
		return authenticationResponseJSONSchema.parse(res)
	}
}
