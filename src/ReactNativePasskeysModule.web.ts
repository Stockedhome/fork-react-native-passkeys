import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type { AuthenticationExtensionsClientOutputsJSON, AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialDescriptorJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from "./ReactNativePasskeys.types";

export default {
	get name(): string {
		return "ReactNativePasskeys";
	},

	isAutoFillAvailable(): Promise<boolean> {
		return browserSupportsWebAuthnAutofill();
	},

	isSupported() {
		return browserSupportsWebAuthn();
	},

	startRegistration(optionsJSON: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON> {
		const promise = startRegistration(optionsJSON as typeof optionsJSON & {
			excludeCredentials: undefined | (PublicKeyCredentialDescriptorJSON & {
				transports: any[];
			})[];
		})

		return promise as Promise<Awaited<typeof promise> & {
			clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
		}>
	},

	startAuthentication(optionsJSON: PublicKeyCredentialRequestOptionsJSON, useBrowserAutofill?: boolean | undefined): Promise<AuthenticationResponseJSON> {
		const promise = startAuthentication(optionsJSON as typeof optionsJSON & {
			allowCredentials: undefined| (PublicKeyCredentialDescriptorJSON & {
				transports: any[];
			})[];
		})

		return promise as Promise<Awaited<typeof promise> & {
			clientExtensionResults: AuthenticationExtensionsClientOutputsJSON;
		}>
	}
};
