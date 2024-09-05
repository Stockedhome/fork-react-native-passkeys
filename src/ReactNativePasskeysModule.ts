import { requireNativeModule } from 'expo-modules-core'
import Constants from 'expo-constants'
import type { AuthenticationResponseJSON, PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON, RegistrationResponseJSON } from './ReactNativePasskeys.types';

interface ReactNativePasskeysNativeModule {
    /** * Android: Calls fido2ApiClient.getRegisterPendingIntent; returns a JSON string representation of RegistrationResponseJSON
     * * iOS: (not reviewed)
     *
     * @returns RegistrationResponseJSON or, as in the case of Android, a string representation of RegistrationResponseJSON
     */
    startRegistration(options: PublicKeyCredentialCreationOptionsJSON): Promise<string | RegistrationResponseJSON>;
    startAuthentication(options: PublicKeyCredentialRequestOptionsJSON): Promise<string | AuthenticationResponseJSON>;
    /** Returns whether the device supports WebAuthn.
     *
     * * Android: Because FIDO2 is part of Google Play Services, everything past Android 5 (API level 21) is supported. As of July 21 2024, https://apilevels.com/ notes that >99.5% of devices support API level 21.
     * * iOS: Must be iOS 15.0 (announced June 2021; released September 2021) or later
     *
     */
    isSupported(): boolean;
    /** Returns whether the device supports auto-fill for WebAuthn credentials.
     *
     * Currently, both iOS and Android return false.
     *
     */
    isAutoFillAvailable(): boolean;
}

let reactNativePasskeysNativeModule: ReactNativePasskeysNativeModule;
try {
    // It loads the native module object from the JSI or falls back to
    // the bridge module (from NativeModulesProxy) if the remote debugger is on.
    reactNativePasskeysNativeModule = requireNativeModule<ReactNativePasskeysNativeModule>('ReactNativePasskeys')
} catch (error) {

    console.error(error) // Log the original error for debugging purposes

    throw new Error(
        'Failed to load native Expo module `ReactNativePasskeys`. Error message: ' + error.message
        + '\n\n'
        + (Constants.appOwnership === 'expo'
            ? 'It looks like you are running inside of Expo Go. In order to load custom native code, you'
            : 'If you are using Expo Go, you')
        + ' will need to switch to a development build instead. Development builds give you the same abilities as Expo Go while also allowing you to use custom native code. More info: https://docs.expo.dev/develop/development-builds/use-development-builds/'
        + '\n\n'
    )
}

export default reactNativePasskeysNativeModule
