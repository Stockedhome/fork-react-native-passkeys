import type { PublicKeyCredentialCreationOptionsJSON as S_PublicKeyCredentialCreationOptionsJSON, AuthenticationResponseJSON as S_AuthenticationResponseJSON } from "@simplewebauthn/typescript-types";
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON } from "./ReactNativePasskeys.types";

export function castFromSimpleWebAuthnRegistrationOptions(options: S_PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptionsJSON {
    return options as typeof options & {
        extensions: Record<any, any>;
    }
}

export function castToSimpleWebAuthnAuthenticationResponse(response: AuthenticationResponseJSON): S_AuthenticationResponseJSON {
    return response as typeof response & {
        clientExtensionResults: any;
    }
}
