# Stockedhome Fork: React Native Passkeys

This is a fork of [peterferguson/react-native-passkeys](https://github.com/peterferguson/react-native-passkeys) with the following changes:
* Android: Largely rewrite to change api from `androidx.credentials.webauthn` to `com.google.android.gms.fido.fido2` to support non-Google authenticators
  * `androidx.credentials.webauthn`, while it allows users to register external authenticators, it does not allow users to authenticate with them
  * `androidx.credentials.webauthn` does not match the flow users may be used to from browsers (Chrome, Firefox, etc.)
* Include `@simplewebauthn/browser` and rewrite this library's JS-side code to match
* Rewrite API names to match `@simplewebauthn/browser`'s API names
* Rewrite API to use return values instead of throwing errors; for a browser API with many obscure errors, this makes it easier to handle them all.
* Validate API returns end-to-end using Zod to ensure APIs return exactly what you expect

Minimum API version has not yet been analyzed/tested but is known to be functional on API 31 (Android 12).

> [!WARNING]
> This fork has not been tested on iOS. It is likely that it will not work on iOS.

> [!WARNING]
> The example app has not been updated to reflect the changes in this fork.

## Library TODOs
* Test on iOS
* Update the example app
* Set up CI/CD to publish to npm

# React Native Passkeys

This is an Expo module to help you create and authenticate with passkeys on iOS, Android & web with the same api. The library aims to stay close to the standard [`navigator.credentials`](https://w3c.github.io/webappsec-credential-management/#framework-credential-management). More specifically, we provide an api for `get` & `create` functions (since these are the functions available cross-platform).

The adaptations we make are simple niceties like providing automatic conversion of base64-url encoded strings to buffer. This is also done to make it easier to pass the values to the native side.

Further niceties include some flag functions that indicate support for certain features.

## Installation

```sh
npx expo install react-native-passkeys
```

## iOS Setup

#### 1. Host an Apple App Site Association (AASA) file

For Passkeys to work on iOS, you'll need to host an AASA file on your domain. This file is used to verify that your app is allowed to handle the domain you are trying to authenticate with. This must be hosted on a site with a valid SSL certificate.

The file should be hosted at:

```
https://<your_domain>/.well-known/apple-app-site-association
```

Note there is no `.json` extension for this file but the format is json. The contents of the file should look something like this:

```json
{
  "webcredentials": {
    "apps": ["<teamID>.<bundleID>"]
  }
}
```

Replace `<teamID>` with your Apple Team ID and `<bundleID>` with your app's bundle identifier.

#### 2. Add Associated Domains

Add the following to your `app.json`:

```json
{
  "expo": {
    "ios": {
      "associatedDomains": ["webcredentials:<your_domain>"]
    }
  }
}
```

Replace `<your_domain>` with the domain you are hosting the AASA file on. For example, if you are hosting the AASA file on `https://example.com/.well-known/apple-app-site-association`, you would add `example.com` to the `associatedDomains` array.

#### 3. Prebuild and run your app

```sh
npx expo prebuild -p ios
npx expo run:ios # or build in the cloud with EAS
```

## Android Setup

#### 1. Host an `assetlinks.json` File

For Passkeys to work on Android, you'll need to host an `assetlinks.json` file on your domain. This file is used to verify that your app is allowed to handle the domain you are trying to authenticate with. This must be hosted on a site with a valid SSL certificate.

The file should be hosted at:

```
https://<your_domain>/.well-known/assetlinks.json
```

and should look something like this:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "<package_name>",
      "sha256_cert_fingerprints": ["<sha256_cert_fingerprint>"]
    }
  }
]
```

Replace `<package_name>` with your app's package name and `<sha256_cert_fingerprint>` with your app's SHA256 certificate fingerprint.

#### 2. Modify Expo Build Properties

Next, you'll need to modify the `compileSdkVersion` in your `app.json` to be at least 34.

```json
{
  "expo": {
    "plugins": [
      [
        "expo-build-properties",
        {
          "android": {
            "compileSdkVersion": 34
          }
        }
      ]
    ]
  }
}
```

#### 3. Prebuild and run your app

```sh
npx expo prebuild -p android
npx expo run:android # or build in the cloud with EAS
```
