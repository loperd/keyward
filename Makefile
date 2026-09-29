.PHONY: build test install uninstall status run fmt deploy

build:
	cargo build

test:
	cargo test
	./scripts/smoke.sh

install:
	./scripts/install.sh install

# Installing without rebuilding — when the release is already built.
install-fast:
	./scripts/install.sh install --no-build

uninstall:
	./scripts/install.sh uninstall

status:
	./scripts/install.sh status

run:
	cd gui && npm run tauri dev

fmt:
	cargo fmt

# ── Publishing the plugins to the catalogue ─────────────────────────────
#
# `make install` is about this machine, `make deploy` about other people's: it
# builds the plugins' packages for the current platform and puts them into R2,
# which is where the daemon installs them from.
#
#   make deploy DRY=1   — the same thing into dist/registry/, with no network
#   make deploy         — for real; needs CLOUDFLARE_API_TOKEN and
#                         CLOUDFLARE_ACCOUNT_ID, or it refuses in plain words
#
# The publisher's key is KEYWARD_PUBLISHER_KEY, by default
# ~/.keyward/publisher.key. The private half does not reach the repository and
# must not.
# Every plugin in the tree: a directory under crates/plugins with a plugin.json.
PLUGINS ?= $(notdir $(patsubst %/,%,$(dir $(wildcard crates/plugins/*/plugin.json))))
PUBLISHER_KEY ?= $(if $(KEYWARD_PUBLISHER_KEY),$(KEYWARD_PUBLISHER_KEY),$(HOME)/.keyward/publisher.key)
DEPLOY_FLAGS = $(if $(DRY),--dry-run,)

deploy:
	@target=$$(rustc -vV | awk '/^host:/{print $$2}'); \
	for id in $(PLUGINS); do \
	  ./scripts/plugin-package.sh $$id --target $$target || exit 1; \
	  ./scripts/plugin-publish.sh dist/packages/$$id \
	    --platform $$target --key "$(PUBLISHER_KEY)" $(DEPLOY_FLAGS) || exit 1; \
	done
