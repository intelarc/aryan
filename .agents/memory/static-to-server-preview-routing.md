---
name: Static-to-server preview routing
description: Replit preview routing pitfalls when converting a static site into a server-backed app.
---

When replacing a static serving workflow with a web server, removing the old workflow may leave its process running. Also verify the existing Replit dev domain, not only the new server's local port; the domain can continue routing to the old port unless the `.replit` port map is updated to the server's port.

**Why:** A stale static server and an unchanged external port mapping can continue serving the unprotected original page even while the new gated server appears healthy.

**How to apply:** After a static-to-server conversion, stop the old server process, map the dev domain's external port to the new server port, and verify the domain itself returns the protected response.
