#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# patch-template-ftl.sh
#
# Patches the Keycloak default login template.ftl to inject the GKTinc
# JavaScript variable just before </head>.
#
# The variable ${gktinc_javascript} is set by GKTincLoginFormsProvider and
# contains the client-side GKTinc script block (or an empty string when GKTinc
# is not active for the current request).
#
# Usage (inside the Keycloak container, after kc.sh build):
#   bash /opt/keycloak/scripts/patch-template-ftl.sh
#
# Or from the host before building the Docker image:
#   KEYCLOAK_HOME=/opt/keycloak bash scripts/patch-template-ftl.sh
# -----------------------------------------------------------------------------

set -euo pipefail

KEYCLOAK_HOME="${KEYCLOAK_HOME:-/opt/keycloak}"
THEMES_JAR_GLOB="${KEYCLOAK_HOME}/lib/lib/main/org.keycloak.keycloak-themes-*.jar"
CUSTOM_THEME_DIR="${KEYCLOAK_HOME}/themes/custom/login"
TARGET_FTL="${CUSTOM_THEME_DIR}/template.ftl"

# ---------------------------------------------------------------------------
# 1. Locate the themes JAR
# ---------------------------------------------------------------------------
THEMES_JAR=""
for f in ${THEMES_JAR_GLOB}; do
    [ -f "$f" ] && THEMES_JAR="$f" && break
done

if [ -z "$THEMES_JAR" ]; then
    echo "ERROR: Keycloak themes JAR not found at ${THEMES_JAR_GLOB}" >&2
    exit 1
fi

echo "Found themes JAR: ${THEMES_JAR}"

# ---------------------------------------------------------------------------
# 2. Extract template.ftl from the keycloak (base) login theme inside the JAR
# ---------------------------------------------------------------------------
mkdir -p "${CUSTOM_THEME_DIR}"

# The path inside the JAR is: theme/keycloak/login/template.ftl
ENTRY_PATH="theme/keycloak/login/template.ftl"
ENTRY_PATH2="theme/base/login/template.ftl"

if ! unzip -p "${THEMES_JAR}" "${ENTRY_PATH}" > "${TARGET_FTL}"; then
    echo "ERROR: Could not extract ${ENTRY_PATH} from ${THEMES_JAR}" >&2
    #exit 1
    # try ENTRY_PATH2
    if ! unzip -p "${THEMES_JAR}" "${ENTRY_PATH2}" > "${TARGET_FTL}"; then
        echo "ERROR: Could not extract ${ENTRY_PATH2} from ${THEMES_JAR}" >&2
        exit 1
    else
        ENTRY_PATH="${ENTRY_PATH2}"
    fi
fi

echo "Extracted: ${ENTRY_PATH} -> ${TARGET_FTL}"

# ---------------------------------------------------------------------------
# 3. Patch: inject ${gktinc_javascript} just before </head>
#    Uses a sentinel comment to make the patch idempotent.
# ---------------------------------------------------------------------------
SENTINEL="gktinc_javascript"

if grep -q "${SENTINEL}" "${TARGET_FTL}"; then
    echo "Template already patched — skipping sed."
    exit 0
fi

# The FreeMarker snippets render only when the variable is defined, so it is
# safe to include both in every page (non-GKTinc / non-XE pages get an empty
# string for the missing one).
INJECT_GKTINC='<#if gktinc_javascript??>${gktinc_javascript}</#if>'
INJECT_GKXE='<#if gkxe_javascript??>${gkxe_javascript?no_esc}</#if>'

# sed: insert both snippets on the line immediately before </head>
sed -i "s|</head>|${INJECT_GKTINC}\n${INJECT_GKXE}\n</head>|" "${TARGET_FTL}"

if grep -q "${SENTINEL}" "${TARGET_FTL}"; then
    echo "Patch applied successfully to ${TARGET_FTL}"
else
    echo "ERROR: sed did not modify the file. Check that </head> exists in ${TARGET_FTL}" >&2
    exit 1
fi
