#!/bin/bash
# Development Jenkins Pipeline for Testing Git-based Salt Packaging Workflow
# This script tests the migration from OBS to git-based package maintenance
# using development repositories and branches.

set -e  # Exit on any error

# Valid gitea token for src.opensuse.org
GITEA_TOKEN=$(grep --only-matching --perl-regexp 'machine\s+src.opensuse.org\s+login\s+\S+\s+password\s+\K\S+' ~/.netrc)

# Development Configuration
GITEA_PACKAGE_GIT="ygutierrez/salt"  
GITHUB_SOURCE_GIT="https://github.com/ycedres/salt-1"
GITHUB_BRANCH="embed-packaging"
OBS_DEV_PROJECT="home:ygutierrez:branches:systemsmanagement:saltstack"



# Phase setting: controls what the pipeline does
PHASE=1  # Always dry run
# PHASE=2  # Always push to Gitea
# PHASE=3  # Always full test with OBS
MODE=pr

echo "=========================================="
echo "Salt Packaging Workflow - Development Test"
echo "=========================================="
echo "Mode: ${MODE} (push=direct, pr=pull-request)"
echo "Phase: ${PHASE}"
echo "Gitea Package-Git: ${GITEA_PACKAGE_GIT}"
echo "GitHub Source-Git: ${GITHUB_SOURCE_GIT}#${GITHUB_BRANCH}"
echo "OBS Project: ${OBS_DEV_PROJECT}"
echo "=========================================="

PHASE=${PHASE:-1}
# Workflow mode
MODE=${MODE:-push}

  # Check curl is available
  if ! command -v curl &> /dev/null; then
      echo "ERROR: curl is not installed"
      exit 1
  fi
  echo "curl is available" 

  # Check GITEA_TOKEN is set
  if [ -z "$GITEA_TOKEN" ]; then
      echo "ERROR: GITEA_TOKEN is not set"
      echo "  Check ~/.netrc contains entry for src.opensuse.org"
      exit 1
  fi
  echo "GITEA_TOKEN is set"
  
  # Test Gitea API authentication
  echo -n "Testing Gitea API authentication... "
  if ! curl -f -s -H "Authorization: token ${GITEA_TOKEN}" \
      https://src.opensuse.org/api/v1/user > /dev/null 2>&1; then
      echo "FAILED"
      echo "ERROR: Cannot authenticate to Gitea API"
      echo "  Check that your token is valid"
      echo "  Generate new token at: https://src.opensuse.org/user/settings/applications"
      exit 1
  fi
  echo "OK"

# Step 1: Clone Package-Git repository from Gitea
echo "Step 1: Cloning Package-Git from Gitea..."
test -d salt && rm -rf salt
git clone -q "https://${GITEA_TOKEN}@src.opensuse.org/${GITEA_PACKAGE_GIT}" salt

pushd salt

# Step 2: Track all remote branches
echo "Step 2: Tracking all remote branches..."
git branch -r | grep -v -e '\->' -e "origin/$(git branch --show-current)" | while read -r remote; do
    git branch --track "${remote#origin/}" "$remote" 2>/dev/null || true
done

popd

# Step 3: Run make update to sync from GitHub Source-Git
cd salt

echo "Step 3: Running make update..."
if [ "${PHASE}" -eq 1 ]; then
    echo "Phase 1: Dry run (GIT_PUSH=0)"
    make update \
        SALT_REPO="${GITHUB_SOURCE_GIT}" \
        SALT_BRANCH="${GITHUB_BRANCH}" \
        GIT_PUSH=0
    echo "Dry run completed."
    echo "No changes were pushed to Gitea."

elif [ "${PHASE}" -eq 2 ]; then
    echo "Phase 2: Update with git push (GIT_PUSH=1)"
    make update \
        SALT_REPO="${GITHUB_SOURCE_GIT}" \
        SALT_BRANCH="${GITHUB_BRANCH}" \
        GIT_PUSH=1
    echo "Update completed and pushed to Gitea."
    echo "Check: https://src.opensuse.org/${GITEA_PACKAGE_GIT}"

elif [ "${PHASE}" -eq 3 ]; then
    echo "Phase 3: Full test with OBS submission"
    make update \
        SALT_REPO="${GITHUB_SOURCE_GIT}" \
        SALT_BRANCH="${GITHUB_BRANCH}" \
        GIT_PUSH=1
    echo "Update completed and pushed to Gitea."

    echo ""
    echo "Step 4: Testing OBS submission..."
    make factory-submit-test \
        OBS_PROJECT="${OBS_DEV_PROJECT}"
    echo "OBS submission completed."
    echo "Check: https://build.opensuse.org/package/show/${OBS_DEV_PROJECT}/salt"

else
    echo "ERROR: Invalid PHASE value: ${PHASE}"
    echo "  Valid values: 1 (dry run), 2 (git push), 3 (full test)"
    exit 1
fi

echo ""
echo "=========================================="
echo "Pipeline completed successfully!"
echo "=========================================="
