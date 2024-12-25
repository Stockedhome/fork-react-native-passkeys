import { WebAuthnError as SimpleWebAuthnError, type WebAuthnErrorCode } from '@simplewebauthn/browser';
import { Platform } from 'expo-modules-core';
import type { startAuthentication, startRegistration } from '.';

export enum WebAuthnError {
	UnknownError = 'Unknown Error',
	NotSupportedAtAll = 'This device/browser does not support WebAuthn at all',
	AutofillNotSupported = 'Browser does not support WebAuthn autofill',
	NoAutofillTarget = 'No <input> with "webauthn" as the only or last value in its `autocomplete` attribute was detected',
	AuthNotCompleted = 'Authentication was not completed',
	// literally impossible to hit 'options was missing required publicKey property'
	AbortedByProgrammer = 'The request was canceled through the use of a JS AbortSignal',
	NoAuthenticatorsSupportDiscoverableCredentials = 'The request required Discoverable credentials but no authenticators support them',
	NoAuthenticatorsSupportUserVerification = 'The request required User Verification but no authenticators support it',
	AuthenticatorPreviouslyRegistered = 'The authenticator was previously registered',
	SecurityOrPrivacyIssueOrUserClosed = 'The user device determined that the request could not be completed due to a security/privacy issue OR the user closed the dialog',
	InvalidOptions_NotPublicKey = 'No entry in pubKeyCredParams was of type "public-key"',
	NoCommonAlgorithms = 'The client device and web server do not have any common algorithms between them; they don\'t know how to communicate passkeys with each other',
	RelayingPartyIDNotValidHostname = 'The Relaying Party ID is not a valid hostname',
	WrongRelayingPartyID = 'The server sent us a Relaying Party ID that does not match the domain of the current page; we cannot continue for security reasons',
	UserIdInvalidLength = 'User ID was not between 1 and 64 characters',
	GeneralAuthenticationError = 'The authenticator was unable to process the specified options, or could not create a new assertion signature',
	UserCanceled = 'User canceled the request',
	NoCredentialsOnDevice = 'No credentials for this username are stored on this device',
	NotAllowedByServer = 'The server did not explicitly allow this request (you may want to check Asset Links for Android or Apple App Site Association for iOS)',
}

type WebAuthnOptions = Parameters<typeof startRegistration>[0] | Parameters<typeof startAuthentication>[0]

export type WebAuthnErrorInfo = [error: WebAuthnError, additionalContext: string | null, options: WebAuthnOptions | null]

// Don't want to import Node types, not do we want to override the global `process` type
type GlobalProcessType = undefined | { env?: { NODE_ENV: 'development' | 'production' } }
declare const process: GlobalProcessType | undefined;


export function errorMessageToEnumValue(messageOrCode: WebAuthnErrorCode | string & {}, error: unknown, authOrRegistration: 'authentication' | 'registration', options: WebAuthnOptions): WebAuthnErrorInfo {

	const simpleWANInvalidRPHostnameMessage = window?.location?.hostname && `${window?.location?.hostname} is an invalid domain`
	const simpleWANWrongRPMessage = messageOrCode.startsWith(`The RP ID "`) && messageOrCode.endsWith(`" is invalid for this domain`) ? messageOrCode : null;

	// A lot of these cases will just be the same as the SimpleWebAuthn message
	// but different platforms will likely have different messages which is why we need this function
	switch (messageOrCode) {
		case 'WebAuthn is not supported in this browser':
			return [WebAuthnError.NotSupportedAtAll, null, options];

		case WebAuthnError.AutofillNotSupported:
			return [WebAuthnError.AutofillNotSupported, null, options];

		case WebAuthnError.NoAutofillTarget:
			return [WebAuthnError.NoAutofillTarget, null, options];

		case WebAuthnError.AuthNotCompleted:
			return [WebAuthnError.AuthNotCompleted, null, options];

		case 'Registration ceremony was sent an abort signal':
		case 'ERROR_CEREMONY_ABORTED':
			return [WebAuthnError.AbortedByProgrammer, null, options];

		case 'Discoverable credentials were required but no available authenticator supported it':
		case 'ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT':
			return [WebAuthnError.NoAuthenticatorsSupportDiscoverableCredentials, null, options];

		case 'User verification was required but no available authenticator supported it':
		case 'ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT':
			return [WebAuthnError.NoAuthenticatorsSupportUserVerification, null, options];

		case WebAuthnError.AuthenticatorPreviouslyRegistered:
		case 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED':
			return [WebAuthnError.AuthenticatorPreviouslyRegistered, null, options];

		case 'NotAllowedError':
		case 'CredentialContainer request is not allowed.':
		case 'The operation either timed out or was not allowed. See: https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.':
			return [WebAuthnError.SecurityOrPrivacyIssueOrUserClosed, null, options];

		case WebAuthnError.InvalidOptions_NotPublicKey:
		case 'ERROR_MALFORMED_PUBKEYCREDPARAMS':
			return [WebAuthnError.InvalidOptions_NotPublicKey, null, options];

		case 'No available authenticator supported any of the specified pubKeyCredParams algorithms':
		case 'ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG':
			return [WebAuthnError.NoCommonAlgorithms, null, options];

		case 'Cannot find credential in local KeyStore or database':
			return [WebAuthnError.NoCredentialsOnDevice, null, options];

		case WebAuthnError.UserCanceled:
			return [WebAuthnError.UserCanceled, null, options];

		case simpleWANInvalidRPHostnameMessage:
		case 'ERROR_INVALID_DOMAIN':
			return [WebAuthnError.RelayingPartyIDNotValidHostname, simpleWANInvalidRPHostnameMessage, options];

		case simpleWANWrongRPMessage:
		case 'ERROR_INVALID_RP_ID':
			return [WebAuthnError.WrongRelayingPartyID, simpleWANWrongRPMessage, options];

		case WebAuthnError.UserIdInvalidLength:
		case 'ERROR_INVALID_USER_ID_LENGTH':
			return [WebAuthnError.UserIdInvalidLength, null, options];

		case WebAuthnError.GeneralAuthenticationError:
		case 'ERROR_AUTHENTICATOR_GENERAL_ERROR':
			return [WebAuthnError.UnknownError, null, options];

		case 'The incoming request cannot be validated':
			return [WebAuthnError.NotAllowedByServer, Platform.OS, options];

		case 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY': // should not come through but, just in case, we catch this too
			return[WebAuthnError.UnknownError, error && error instanceof SimpleWebAuthnError ? error.message : null, options];
	}

	if (typeof process !== 'undefined' && process && typeof process === 'object' && process.env?.NODE_ENV === 'development') {
		console.error(`Unknown error message during WebAuthn ${authOrRegistration}: "${messageOrCode}"; please report this to the maintainer of @stockedhome/react-native-passkeys`);
		throw error;
	}

	return [WebAuthnError.UnknownError, null, options];
}
