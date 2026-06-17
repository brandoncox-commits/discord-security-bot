---
title: Privacy Policy
---

# Privacy Policy — Discord Security & Moderation Bot

**Effective date:** 17 June 2026
**Contact:** brandon.cox@hotmail.co.uk

This Privacy Policy explains what data the Discord Security & Moderation Bot
("the Bot", "we", "us") accesses and stores when it is added to a Discord
server ("guild"). By adding the Bot to a server you agree to this policy.

## 1. Who controls the Bot

The Bot is operated by the individual identified in the Contact section above.
It is a self-hosted moderation tool. It is not affiliated with Discord Inc.

## 2. Data the Bot accesses

To perform its moderation functions the Bot reads the following data **at the
moment a command is run**. This data is processed in memory to carry out the
requested action and, except where stated in Section 3, is **not stored**:

- **Server, channel, and thread information** (names, IDs, permission overwrites).
- **Role and permission data** (used by `/audit-permissions`).
- **Member and user identifiers** (used by `/bulk-purge-user` and `/trace-app`).
- **Message metadata** — message author ID, timestamp, and, for user-installed
  apps, the interaction metadata that identifies who invoked the app. The Bot
  reads message content only as needed to bulk-delete a targeted user's
  messages; it does **not** store message content.
- **Webhooks, invites, and integrations** (used by `/purge-webhooks`,
  `/wipe-invites`, and `/audit-permissions`).

## 3. Data the Bot stores

The Bot stores the **minimum** required to function:

- **Panic-lock state** (`panic_state.json`): when `/panic lock` is used, the Bot
  stores the affected guild ID, channel IDs, the previous `@everyone` permission
  values for those channels, the name of the moderator who triggered it, and a
  timestamp. This exists solely so `/panic unlock` can restore channels to their
  exact prior state. It is **deleted** for a guild as soon as that guild is
  unlocked.
- **Operational logs**: standard application logs (timestamps, command names,
  error messages) used for debugging and abuse prevention. These may include
  user/guild IDs but not message content.

The Bot keeps **no** database of users, messages, or message content, and does
**not** build profiles or track behaviour over time.

## 4. Action logging inside your server

Several commands post an audit summary to a channel named `#mod-logs` **in your
own server**. That content lives in your server under your control, not on our
systems, and is governed by Discord's own policies.

## 5. How data is used

Accessed and stored data is used **only** to perform the moderation action you
request and to keep the Bot running securely. We do **not** sell, rent, share,
or transfer your data to third parties, and we do **not** use it for advertising
or analytics.

## 6. Data retention

- In-memory data is discarded as soon as the command completes.
- Panic-lock state is retained only until the guild is unlocked.
- Operational logs are retained for a short period for debugging and then
  rotated/deleted.
- Removing the Bot from your server ends all further data access. Any residual
  panic-lock state for that guild can be deleted on request.

## 7. Your rights

Server administrators may request deletion of any stored data relating to their
guild by contacting us at the address above. Because the Bot stores so little,
fulfilling such requests is typically immediate.

## 8. Security

Data is processed on a private, access-controlled host. The bot token and
configuration are stored with restricted file permissions. No system is
perfectly secure, but we apply reasonable measures to protect the limited data
the Bot handles.

## 9. Children

The Bot is intended for use on Discord, which requires users to be at least 13
(or older where local law requires). It is not directed at children under 13.

## 10. Changes

We may update this policy. Material changes will be reflected by updating the
effective date above. Continued use of the Bot after a change constitutes
acceptance of the revised policy.

## 11. Contact

Questions or data requests: **brandon.cox@hotmail.co.uk**
