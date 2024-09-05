# no # ! /usr/bin/env bash
#
#set -eo pipefail
#
#script_dir="$(dirname "$0")"
#
#export EXPO_NONINTERACTIVE=1
#
#echo "Configuring module"
#"$script_dir/expo-module-clean"
#"$script_dir/expo-module-build"
#
#extra_module_build_types=("plugin" "cli" "utils" "scripts")
#for i in "${extra_module_build_types[@]}"
#do
#  if [[ -d "$i" ]]; then
#    echo "Configuring $i"
#    "$script_dir/expo-module-clean" "$i"
#    "$script_dir/expo-module-build" "$i"
#  fi
#done

$env:EXPO_NONINTERACTIVE=1

Write-Host "Configuring module" -ForegroundColor Cyan

# $script_dir doubles as CWD for us here
$script_dir = Split-Path -Parent $MyInvocation.MyCommand.Path

# clean
##!/usr/bin/env bash
#
#set -eo pipefail
#
#if [[ ! -f package.json ]]; then
#  echo "The current working directory is not a package's root directory"
#  exit 1
#fi
#
#directory=$1
## Support `yarn clean plugin` to delete ./plugin/build/
#if [[ -n $directory ]]; then
#  rm -rf "$directory/build"
#else
#  rm -rf build
#fi

if (-not (Test-Path package.json)) {
    Write-Host "The current working directory is not a package's root directory" -ForegroundColor Red
    exit 1
}

if (Test-Path "$script_dir/build") {
    Remove-Item -Recurse -Force "$script_dir/build"
}


# build
# #!/usr/bin/env bash
#
# set -eo pipefail
#
# script_dir="$(dirname "$0")"
#
# args=("$@")
#
# # If the command is used like `yarn build plugin`, set the --build option to point to
# # plugin/tsconfig.json
# extra_module_build_types=("plugin" "cli" "utils" "scripts")
# for i in "${extra_module_build_types[@]}"
# do
#   if [ "$1" == "$i" ]; then
#     # Check if tsconfig.json exists in the directory
#     if [ -f "$(pwd)/$i/tsconfig.json" ]; then
#       # `--build` must be the first argument, so reset the array
#       args=()
#       args+=("--build")
#       args+=("$(pwd)/$i")
#       # Push the rest of the arguments minus the `plugin` arg
#       args+=("${@:2}")
#     else
#       echo "tsconfig.json not found in $@, skipping build for $@/"
#       exit
#     fi
#   fi
# done
#
# if [[ -t 1 && (-z "$CI" && -z "$EXPO_NONINTERACTIVE") ]]; then
#   args+=("--watch")
# fi
#
# "$script_dir/expo-module-tsc" "${args[@]}"

$_args = $args

$extra_module_build_types = @("plugin", "cli", "utils", "scripts")

foreach ($i in $extra_module_build_types) {
    if ($args[0] -eq $i) {
        if (Test-Path "$script_dir/$i/tsconfig.json") {
            $_args = @()
            $_args += "--build"
            $_args += "$script_dir/$i"
            $_args += $args[1..($args.Length - 1)]
        } else {
            Write-Host "tsconfig.json not found in $args, skipping build for $args/" -ForegroundColor Red
            exit
        }
    }
}

if ($Host.UI.RawUI.BackgroundColor -eq "Black" -and (-not $env:CI -and -not $env:EXPO_NONINTERACTIVE)) {
    $_args += "--watch"
}

# tsc
# #!/usr/bin/env bash
#
# set -eo pipefail
#
# script_dir="$(dirname "$0")"
#
# "$script_dir/npx" tsc "$@"

& pnpm exec tsc $_args
