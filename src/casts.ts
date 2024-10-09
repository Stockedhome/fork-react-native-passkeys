import type { PublicKeyCredentialCreationOptionsJSON as S_PublicKeyCredentialCreationOptionsJSON, AuthenticationResponseJSON as S_AuthenticationResponseJSON, RegistrationResponseJSON as S_RegistrationResponseJSON, AuthenticatorAttestationResponseJSON as S_AuthenticatorAttestationResponseJSON, PublicKeyCredentialRequestOptionsJSON as S_PublicKeyCredentialRequestOptionsJSON, PublicKeyCredentialDescriptorJSON as S_PublicKeyCredentialDescriptorJSON, AuthenticationExtensionsClientOutputs as S_AuthenticationExtensionsClientOutputs } from "@simplewebauthn/typescript-types";
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, RegistrationResponseJSON, PublicKeyCredentialRequestOptionsJSON } from "./ReactNativePasskeys.types";

export function castFromSimpleWebAuthnRegistrationOptions(options: S_PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptionsJSON {
    if (!options.rp.id) throw new TypeError('[castFromSimpleWebAuthnRegistrationOptions] rp.id is required');
    return options as typeof options & {
        rp: typeof options['rp'] & {
            id: NonNullable<typeof options['rp']['id']>;
        };
        extensions: Record<any, any>;
    }
}

export function castToSimpleWebAuthnRegistrationResponse(response: RegistrationResponseJSON): S_RegistrationResponseJSON {
    return response as typeof response & {
        response: S_AuthenticatorAttestationResponseJSON;
        clientExtensionResults: S_AuthenticationExtensionsClientOutputs;
    }
}

export function castFromSimpleWebAuthnAuthenticationOptions(options: PublicKeyCredentialRequestOptionsJSON): S_PublicKeyCredentialRequestOptionsJSON {
    return options as typeof options & {
        allowCredentials?: S_PublicKeyCredentialDescriptorJSON[];
        extensions?: AuthenticationExtensionsClientInputs;
    }
}

export function castToSimpleWebAuthnAuthenticationResponse(response: AuthenticationResponseJSON): S_AuthenticationResponseJSON {
    return response as typeof response & {
        clientExtensionResults: any;
    }
}
