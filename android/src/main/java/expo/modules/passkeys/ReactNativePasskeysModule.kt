package expo.modules.passkeys

import AuthenticatorAssertionResponseJSON
import AuthenticatorSelectionCriteria
import PublicKeyCredentialCreationOptions
import PublicKeyCredentialDescriptor
import PublicKeyCredentialParameters
import PublicKeyCredentialRequestOptions
import PublicKeyCredentialRpEntity
import PublicKeyCredentialUserEntity
import com.google.gson.Gson
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import com.facebook.react.bridge.ActivityEventListener
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.Fido2ApiClient
import com.google.android.gms.tasks.Task
import com.facebook.react.bridge.ReactApplicationContext
import com.google.android.gms.fido.fido2.api.common.AttestationConveyancePreference
import android.util.Base64
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAssertionResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorAttestationResponse
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential

//
// Lots of code was either taken from or inspired by
// the Fido2 project in Google's repo android/identity-samples
//
// https://github.com/android/identity-samples/
//

private const val BASE64_FLAG = Base64.NO_PADDING or Base64.NO_WRAP or Base64.URL_SAFE

fun ByteArray.toBase64(): String {
    return Base64.encodeToString(this, BASE64_FLAG)
}

fun String.decodeBase64(): ByteArray {
    return Base64.decode(this, BASE64_FLAG)
}

//import okio.ByteString.Companion.decodeBase64

class ReactNativePasskeysModule : Module() {

    private lateinit var fido2ApiClient: Fido2ApiClient

    override fun definition() = ModuleDefinition {
        Name("ReactNativePasskeys")

        fido2ApiClient = Fido.getFido2ApiClient(appContext.reactContext!!)

        val reactContext = appContext.reactContext!! as ReactApplicationContext // Expo abstracts the type but it's always a ReactApplicationContext according to their own internal types
        reactContext.addActivityEventListener(ReactNativePasskeysActivityEventListener(reactContext))

        Function("isSupported") {
            val minApiLevelPasskeys = 21 // Android 5; As of July 21, https://apilevels.com says 99.6% of devices meet this API level and that's all devices
            val currentApiLevel = android.os.Build.VERSION.SDK_INT
            return@Function currentApiLevel >= minApiLevelPasskeys
        }

        Function("isAutoFillAvailable") {
            false
        }

        AsyncFunction("startRegistration") { options: PublicKeyCredentialCreationOptions, promise: Promise ->
            createPromise = promise

            val activity = appContext.currentActivity
            if (activity == null) {
                val e = Exception("Current activity is null! This should not be possible!")
                promise.reject("ActivityNotFound", e.stackTraceToString(), e)
                return@AsyncFunction
            }

            val creationOptions = parsePublicKeyCredentialCreationOptions(options)


            // PERSON WHO JUST WOKE UP
            // TODO LIST:
            // * Turn json into the usable native stuff. Only real way is to parse it manually, unfortunately. Rely on Google's example.
            // * Turn this into a fork of react-native-passkeys
            // * Be awesome; you got this!

            val task: Task<PendingIntent> = fido2ApiClient.getRegisterPendingIntent(creationOptions)
            task.addOnSuccessListener { pendingIntent ->
                try {
                    activity.startIntentSenderForResult(
                        pendingIntent.intentSender,
                        REQUEST_CODE_REGISTER,
                        null,
                        0,
                        0,
                        0
                    )
                } catch (e: Exception) {
                    promise.reject("CreateCredentialError", e.stackTraceToString(), e)
                }
            }.addOnFailureListener { e ->
                promise.reject("CreateCredentialError", e.stackTraceToString(), e)
            }
        }

        AsyncFunction("startAuthentication") { options: PublicKeyCredentialRequestOptions, promise: Promise ->
            getPromise = promise

            val activity = appContext.currentActivity
            if (activity == null) {
                val e = Exception("Current activity is null! This should not be possible!")
                promise.reject("ActivityNotFound", e.stackTraceToString(), e)
                return@AsyncFunction
            }

            val requestOptions = parsePublicKeyCredentialRequestOptions(options)

            val task: Task<PendingIntent> = fido2ApiClient.getSignPendingIntent(requestOptions)
            task.addOnSuccessListener { pendingIntent ->
                try {
                    activity.startIntentSenderForResult(
                        pendingIntent.intentSender,
                        REQUEST_CODE_SIGN,
                        null,
                        0,
                        0,
                        0
                    )
                } catch (e: Exception) {
                    promise.reject("GetCredentialError", e.stackTraceToString(), e)
                }
            }.addOnFailureListener { e ->
                promise.reject("GetCredentialError", e.stackTraceToString(), e)
            }
        }
    }

    companion object {
        const val REQUEST_CODE_REGISTER = 1
        const val REQUEST_CODE_SIGN = 2
        var createPromise: Promise? = null
        var getPromise: Promise? = null
    }


    private fun parsePublicKeyCredentialCreationOptions(
        objToParse: PublicKeyCredentialCreationOptions
    ): com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions {
        val builder = com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions.Builder()
        objToParse.attestation?.let { s ->  builder.setAttestationConveyancePreference(AttestationConveyancePreference.fromString(s)) }
        //builder.setAuthenticationExtensions() //setAuthenticationExtensions      AuthenticationExtensions   --   Not supported
        objToParse.authenticatorSelection?.let { o ->  builder.setAuthenticatorSelection(parseAuthenticatorSelectionCriteria(o)) }
        builder.setChallenge(objToParse.challenge.decodeBase64())
        objToParse.excludeCredentials?.let { l ->  builder.setExcludeList(l.map { o -> parsePublicKeyCredentialDescriptor(o) }) }
        builder.setParameters(objToParse.pubKeyCredParams.map { o -> parsePublicKeyCredentialParameters(o) })
        //builder.setRequestId()
        builder.setRp(parsePublicKeyCredentialRpEntity(objToParse.rp))
        builder.setTimeoutSeconds(objToParse.timeout)
        //builder.setTokenBinding() //setTokenBinding      TokenBinding   --   idek what this is
        builder.setUser(parsePublicKeyCredentialUserEntity(objToParse.user))
        return builder.build()
    }

    private fun parseAuthenticatorSelectionCriteria(
        criteria: AuthenticatorSelectionCriteria
    ): com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria {
        val builder = com.google.android.gms.fido.fido2.api.common.AuthenticatorSelectionCriteria.Builder()
        criteria.authenticatorAttachment?.let { s -> builder.setAttachment(com.google.android.gms.fido.fido2.api.common.Attachment.fromString(s)) }
        builder.setRequireResidentKey(criteria.requireResidentKey)
        criteria.residentKey?.let { s -> builder.setResidentKeyRequirement(com.google.android.gms.fido.fido2.api.common.ResidentKeyRequirement.fromString(s)) }
        return builder.build()
    }

    private fun parsePublicKeyCredentialDescriptor(
        objToParse: PublicKeyCredentialDescriptor
    ): com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor {
        return com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialDescriptor(objToParse.type, objToParse.id.decodeBase64(), objToParse.transports?.map { s -> com.google.android.gms.fido.common.Transport.fromString(s) })
    }

    private fun parsePublicKeyCredentialParameters(
        objToParse: PublicKeyCredentialParameters
    ): com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters {
        return com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialParameters(objToParse.type, objToParse.alg)
    }

    private fun parsePublicKeyCredentialRpEntity(
        objToParse: PublicKeyCredentialRpEntity
    ): com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity {
        return com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRpEntity(objToParse.id, objToParse.name, objToParse.icon)
    }

    //private fun parseTokenBinding(
    //    objToParse: TokenBinding
    //): com.google.android.gms.fido.fido2.api.common.TokenBinding {
    //    return com.google.android.gms.fido.fido2.api.common.TokenBinding(objToParse.something, objToParse.something)
    //}

    private fun parsePublicKeyCredentialUserEntity(
        objToParse: PublicKeyCredentialUserEntity
    ): com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity {
        return com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialUserEntity(objToParse.id.decodeBase64(), objToParse.name, objToParse.icon, objToParse.displayName)
    }


    private fun parsePublicKeyCredentialRequestOptions(
        objToParse: PublicKeyCredentialRequestOptions
    ): com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions {
        val builder = com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialRequestOptions.Builder()
        objToParse.allowCredentials?.let { l -> builder.setAllowList(l.map { o -> parsePublicKeyCredentialDescriptor(o) }) }
        //builder.setAuthenticationExtensions() //setAuthenticationExtensions      AuthenticationExtensions   --   Not supported
        builder.setChallenge(objToParse.challenge.decodeBase64()) // setChallenge   byte
        //builder.setRequestId() // setRequestId   Integer
        builder.setRpId(objToParse.rpId) // setRpId   String
        builder.setTimeoutSeconds(objToParse.timeout) // setTimeoutSeconds   Double
        //builder.setTokenBinding() //setTokenBinding      TokenBinding   --   idek what this is
        return builder.build()
    }


}

private class ReactNativePasskeysActivityEventListener(private val reactContext: ReactApplicationContext) :
    ActivityEventListener {

    override fun onActivityResult(activity: Activity, requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == ReactNativePasskeysModule.REQUEST_CODE_REGISTER) {
            val promise = ReactNativePasskeysModule.createPromise
            //if (resultCode == Activity.RESULT_OK) {
            //    val response = data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
            //    response?.let { r -> promise?.resolve(AuthenticatorAttestationResponse.deserializeFromBytes(r).clientDataJSON) }
            //} else {
            //    val e = Error("Could not create credential")
            //    promise?.reject("CreateCredentialError", e.stackTraceToString(), e)
            //}
            val bytes = data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
            when {
                resultCode != Activity.RESULT_OK -> {
                    val e = Error("Unknown error in passkey registration")
                    promise?.reject("PasskeyCreateUnknownException", e.stackTraceToString(), e)
                } bytes == null -> {
                    val e = Error("No data returned from FIDO2 passkey creation Activity")
                    promise?.reject("PasskeyCreateException", e.stackTraceToString(), e)
                } else -> {
                    val credential = PublicKeyCredential.deserializeFromBytes(bytes)
                    val response = credential.response
                    if (response is AuthenticatorErrorResponse) {
                        val e = Error(response.errorMessage)
                        promise?.reject("PasskeyCreateException", response.errorMessage, e)
                    } else {
                        promise?.resolve(credential.toJson())
                    }
                }
            }
            ReactNativePasskeysModule.createPromise = null
        } else if (requestCode == ReactNativePasskeysModule.REQUEST_CODE_SIGN) {
            val promise = ReactNativePasskeysModule.getPromise
            //if (resultCode == Activity.RESULT_OK) {
            //    val response = data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
            //    response?.let { r -> promise?.resolve(AuthenticatorAssertionResponse.deserializeFromBytes(r).clientDataJSON)}
            //} else {
            //    val e = Error("Could not authenticate with credential")
            //    promise?.reject("GetCredentialError", e.stackTraceToString(), e)
            //}

            val bytes = data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
            when {
                resultCode != Activity.RESULT_OK -> {
                    val e = Error("Unknown error in passkey authentication")
                    promise?.reject("PasskeyGetUnknownException", e.stackTraceToString(), e)
                } bytes == null -> {
                    val e = Error("No data returned from FIDO2 passkey authentication Activity")
                    promise?.reject("PasskeyGetException", e.stackTraceToString(), e)
                } else -> {
                    val credential = PublicKeyCredential.deserializeFromBytes(bytes)
                    val response = credential.response
                    if (response is AuthenticatorErrorResponse) {
                        val e = Error(response.errorMessage)
                        promise?.reject("PasskeyGetException", response.errorMessage, e)
                    } else {
                        promise?.resolve(credential.toJson())
                    }
                }
            }
            ReactNativePasskeysModule.getPromise = null
        }
    }

    override fun onNewIntent(intent: Intent?) {
        // do nothing; idk react said to define this so I defined it
    }
}
