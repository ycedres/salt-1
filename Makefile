#### Update Salt Package Git
##
##
## Assumptions:
## 1. There is one branch in the Package-Git per maintained code stream
## 2. openSUSE/salt contains one changelog file per maintained code stream
## 3. Makefile is used inside the Package-Git repo
##
##
## NOTE: The approach taken updates one code stream / branch after another. A potential
# improvement would be to compute different make targets, one for each branch, and execute
# them in parallel. Such an approach needs to use different git checkouts or git worktrees
# to not mix code streams.

## Public Variables
# DEBUG - no default
# MSG - no default
BRANCHES ?= $(shell git branch -r | sed -e '/HEAD/d' -e 's,origin/,,')
CODESTREAMS ?= $(shell git branch -l sle-* | tr -d '[:blank:]*')
SALT_REPO ?= https://github.com/openSUSE/salt
SALT_BRANCH ?= openSUSE/release/3006.0
OBS_API ?= https://api.suse.de
GIT_PUSH ?= 1
GITEA_OWNER ?= salt
GITEA_REPO ?= salt

## Internal Variables
SHELL=/bin/bash

# The variable below uses the "Splitting without adding whitespace trick".
# By default make replaces '\\n' with a single space. Using '$\\n' removes the space.
# See `info make 'Splitting Lines'` for more information.

# comma-separated list of files to extract, expanded by the shell's Pathname expansion
# usage: pkg/suse/{$(pkg_suse_files)}
pkg_suse_files := README.SUSE,_multibuild,salt.spec,update-documentation.sh$\
  ,transactional_update.conf,salt-tmpfiles.d,html.tar.bz2

# comma-separated list of files tracked in the package git repository, expanded
# by the shell's Pathname expansion
# usage: {$(git_tracked_files)}
git_tracked_files := $(pkg_suse_files),salt,salt.changes

# Save the used makefile to pass it to sub-make invocations later
this_file := $(lastword $(MAKEFILE_LIST))
sub_make_flags := -f $(this_file)

# TMPDIR is defined in the parent make process and passed to sub-make
ifndef TMPDIR
TMPDIR := $(shell mktemp -d)
export TMPDIR
endif

# Pass --no-print-directory to sub-make when DEBUG is not set
ifndef DEBUG
sub_make_flags += --no-print-directory
endif

## "Shell Functions"
# usage: $(SHELL) -c '$(function-name)'

define git_maybe_commit
git add {$(git_tracked_files)}; \
if git status --porcelain --untracked-files=no | grep -q "."; \
then \
	git commit --message \
		"$$([ -n "$(MSG)" ] && echo "$(MSG)" \
		|| echo Update to openSUSE/salt@$$(cd $$TMPDIR/salt && git rev-parse --short HEAD))" ;\
else \
	echo "No changes to commit" ;\
fi
endef

define git_maybe_push
if (( $$(git rev-list --count @{u}..HEAD) > 0 )); \
then \
	git push origin ;\
fi
endef

## Targets

# Update branches in $BRANCHES (default: all git branches)
.PHONY: update
update:
	@echo "Update branches:$(patsubst %,'%', $(BRANCHES))"
	@echo Cache salt from $(SALT_REPO)#$(SALT_BRANCH)
	@git clone --quiet --depth 1 --branch $(SALT_BRANCH) $(SALT_REPO) $(TMPDIR)/salt
	@$(foreach branch,$(BRANCHES),$\
		$(MAKE) $(sub_make_flags) update-ipml BRANCH=$(branch);)
	@rm -rf $(TMPDIR)

.PHONY: update-ipml
update-ipml:
	@echo "Update branch: $(BRANCH)"
	@git switch --quiet --force-create $(BRANCH) --track origin/$(BRANCH)
	@cp -r $(TMPDIR)/salt .
	@rm -rf salt/.git*
	@cp salt/pkg/suse/{$(pkg_suse_files)} .
	@cp salt/pkg/suse/changelogs/$(BRANCH).changes salt.changes
	@$(SHELL) -c 'TMPDIR=$(TMPDIR); $(git_maybe_commit)'
ifeq ($(GIT_PUSH), 1)
	@$(SHELL) -c '$(git_maybe_push)'
endif

.PHONY: maintenancerequest mr
mr: maintenancerequest
maintenancerequest:
	@echo "Preparing maintenancerequest for code streams:$(patsubst %, '%', $(CODESTREAMS))"
	@$(foreach cstream,$(CODESTREAMS), $\
		$(MAKE) $(sub_make_flags) mr-impl cstream=$(cstream);)

.PHONY:
mr-impl:
	@echo "Preparing mr for: $(cstream)"
	@git switch --quiet $(cstream)
	@test -d $(TMPDIR)/$(cstream) || mkdir $(TMPDIR)/$(cstream)
	@echo "cd $(TMPDIR)/$(cstream) && osc -A $(OBS_API) branch --checkout --maintenance \
		SUSE:$(shell echo $(cstream) | sed 's/\./-SP/' | tr '[:lower:]' '[:upper:]'):Update \
		salt "
	@echo rsync -a --exclude=.git --exclude=Makefile . $(TMPDIR)/$(cstream)/home:*:branches:*/salt*/
	@echo "cd $(TMPDIR)/$(cstream)/home:*:branches:*/salt*/ \
		&& osc addremove \
		&& osc ci -m 'Update salt' \
		&& osc browse"
	@echo "Please review changes and submit with \`osc mr -m 'jsc#<id>'\`"

.PHONY: factory-submit
factory-submit:
	@echo "Submitting factory to openSUSE:Factory via systemsmanagement:saltstack"
	@git switch --quiet factory
	@test -d $(TMPDIR)/factory-submit || mkdir -p $(TMPDIR)/factory-submit
	@cd $(TMPDIR)/factory-submit && \
		osc -A https://api.opensuse.org co systemsmanagement:saltstack salt
	@rsync -a --exclude=.git --exclude=Makefile --exclude=.osc \
		. $(TMPDIR)/factory-submit/systemsmanagement:saltstack/salt/
	@cd $(TMPDIR)/factory-submit/systemsmanagement:saltstack/salt && \
		osc addremove && \
		osc ci -m "Update to openSUSE/salt@$$(cd $(CURDIR)/salt && git rev-parse --short HEAD)" && \
		osc sr openSUSE:Factory -m "Update Salt to openSUSE/salt@$$(cd $(CURDIR)/salt && git rev-parse --short HEAD)"
	@echo "Submit request created. Check status at https://build.opensuse.org/package/show/systemsmanagement:saltstack/salt"

# Create PRs in Gitea for branches (for branches with PR support)
.PHONY: update-pr
update-pr:
	@echo "Creating PRs for branches:$(patsubst %,'%', $(BRANCHES))"
	@echo Cache salt from $(SALT_REPO)#$(SALT_BRANCH)
	@git clone --quiet --depth 1 --branch $(SALT_BRANCH) $(SALT_REPO) $(TMPDIR)/salt
	@$(foreach branch,$(BRANCHES),$\
		$(MAKE) $(sub_make_flags) update-pr-impl BRANCH=$(branch);)
	@rm -rf $(TMPDIR)

.PHONY: update-pr-impl
update-pr-impl:
	@echo "Creating PR for branch: $(BRANCH)"
	@git fetch origin $(BRANCH):$(BRANCH) 2>/dev/null || true
	@git switch --quiet $(BRANCH)
	@git pull --quiet origin $(BRANCH)
	@UPDATE_BRANCH=update-$(BRANCH)-$(shell date +%Y%m%d-%H%M%S) && \
		COMMIT_HASH=$(shell cd $(TMPDIR)/salt && git rev-parse --short HEAD) && \
		git switch --quiet --force-create $$UPDATE_BRANCH && \
		cp -r $(TMPDIR)/salt . && \
		rm -rf salt/.git* && \
		cp salt/pkg/suse/{$(pkg_suse_files)} . && \
		cp salt/pkg/suse/changelogs/$(BRANCH).changes salt.changes && \
		$(SHELL) -c 'TMPDIR=$(TMPDIR); $(git_maybe_commit)' && \
		if git rev-list --count HEAD^..HEAD | grep -q "^1"; then \
			git push origin $$UPDATE_BRANCH && \
			PR_TITLE="Update $(BRANCH) to openSUSE/salt@$$COMMIT_HASH" && \
			PR_BODY="Automated update from GitHub openSUSE/salt repository." && \
			curl -f -X POST \
				-H "Authorization: token $(GITEA_TOKEN)" \
				-H "Content-Type: application/json" \
				-H "Accept: application/json" \
				-d "{\"head\":\"$$UPDATE_BRANCH\",\"base\":\"$(BRANCH)\",\"title\":\"$$PR_TITLE\",\"body\":\"$$PR_BODY\"}" \
				https://src.opensuse.org/api/v1/repos/$(GITEA_OWNER)/$(GITEA_REPO)/pulls && \
			echo "" && \
			echo "✓ PR created for $(BRANCH)"; \
		else \
			echo "No changes for $(BRANCH), skipping PR creation"; \
			git switch --quiet $(BRANCH); \
			git branch -D $$UPDATE_BRANCH 2>/dev/null || true; \
		fi

html.tar.bz2:
	sh update-documentation.sh salt-maintainers@suse.de --without-sphinx
