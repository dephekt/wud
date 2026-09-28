---
title: Next (Unreleased)
description: Unreleased changes and upcoming features in WUD (What's Up Docker?).
---

# Next (Unreleased)

> Changes below are merged on `main` and will be included in the upcoming release.

- 🚀 [AUTH] Accept OIDC access tokens (RFC 9068) as API bearer tokens with `WUD_AUTH_OIDC_{name}_AUDIENCE`, for service-to-service calls through the client credentials grant
- ⚠️ [AUTH] Personal API Tokens can only be created from a login session, not by a caller authenticated with a bearer token
- 🐛 [API] Running an update trigger (`docker`, `dockercompose`, `command`, `nomad`) through the API is refused unless the trigger is associated with the container (`wud.trigger.include`/`wud.trigger.exclude`, `INCLUDEBYDEFAULT`), and `POST /api/triggers/{type}/{name}` runs it on the stored container rather than the posted one
- 🐛 [UI] Fix container list not updating correctly via SSE events
- 🐛 [WATCHER] Read a newly discovered container's image from the image it runs, not from where its tag points locally, so a container sharing a mutable tag with an already-updated one still reports its update
- 🐛 [TRIGGER] Home Assistant Install button can now run `command`/`nomad` triggers, not just `docker`/`dockercompose`, and honors each container's `wud.trigger.include`/`wud.trigger.exclude` scoping (see getwud/wud#649)

---
