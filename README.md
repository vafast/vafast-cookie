# @vafast/cookie

Vafast Cookie **解析、HMAC 签名校验**与 **`Set-Cookie` 写入**工具包。

| API | 作用 |
|-----|------|
| `cookies()` | 解析 → `next({ cookies })` / `req.cookies` |
| `signedCookies({ secret })` | 校验签名 → `cookies`（未通过）+ `signedCookies`（已通过，值为原文） |
| `createCookieJar(secret?)` | 组装 Cookie，`jar.apply(response)` 写回 |
| `parseCookies` / `serializeCookie` | 头字符串 ↔ Cookie |
| `sign` / `unsign` | HMAC 签名 / 验证（`timingSafeEqual`） |

> 签名 ≠ 加密：值仍可读，只能防篡改。没有 `cookie()` / `setCookie()` 这类导出。

## 安装

```bash
npm install @vafast/cookie
```

## 快速开始

```typescript
import { Server, defineRoute, defineRoutes, err, json, serve } from 'vafast'
import { cookies, signedCookies, createCookieJar } from '@vafast/cookie'

const secret = process.env.COOKIE_SECRET!

const routes = defineRoutes([
  defineRoute({
    method: 'POST',
    path: '/login',
    handler: () => {
      const jar = createCookieJar(secret)
      jar.setSigned('userId', 'u_1', {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax',
        maxAge: 7 * 24 * 3600,
      })
      return jar.apply(json({ ok: true }))
    },
  }),
  defineRoute({
    method: 'GET',
    path: '/profile',
    middleware: [signedCookies({ secret })],
    handler: ({ signedCookies: signed }) => {
      if (!signed.userId) throw err.unauthorized('请先登录')
      return json({ userId: signed.userId })
    },
  }),
  defineRoute({
    method: 'GET',
    path: '/theme',
    middleware: [cookies()],
    handler: ({ cookies: jar }) => json({ theme: jar.theme }),
  }),
])

const server = new Server(routes)
serve({ fetch: server.fetch, port: 3000 })
```

## 选项

### `signedCookies` / `createCookieJar`

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `secret` | `string` | — | HMAC 密钥；`signedCookies` 必填，`setSigned` 时 jar 也必填 |
| `algorithm` | `string` | `'sha256'` | 传给 `crypto.createHmac` |

### `CookieOptions`（`set` / `setSigned` / `serializeCookie`）

| 选项 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `expires` | `Date \| number` | — | 绝对过期时刻（`Expires=`） |
| `maxAge` | `number` | — | 相对存活**秒**数（`Max-Age=`）；与 `expires` 可同时写 |
| `domain` | `string` | — | `Domain`；**删除时必须与写入一致** |
| `path` | `string` | `'/'` | `Path`；**删除时必须与写入一致** |
| `secure` | `boolean` | `false`（不写 Secure） | 仅 HTTPS；`SameSite=None` 时浏览器通常要求开启 |
| `httpOnly` | `boolean` | `true` | 默认禁止 JS 读；显式 `false` 才关闭 |
| `sameSite` | `'Strict' \| 'Lax' \| 'None'` | — | 不传则不写该属性。`Strict` 最严；`Lax` 适合多数会话；`None` 需配 `secure: true` |

### `CookieJar` 方法

| 方法 | 说明 |
|------|------|
| `set(name, value, options?)` | 普通 Cookie |
| `setSigned(name, value, options?)` | 签名 Cookie（需 secret） |
| `delete(name, { domain?, path? }?)` | 写 `Max-Age=0` + 过去 `Expires`；path/domain 须匹配 |
| `apply(response)` | append 所有 `Set-Cookie` 到新 `Response` |

## 文档

完整白话说明（`expires` vs `maxAge`、SameSite、签名 vs 加密、删除匹配）见站点文档：[Cookie 中间件](https://vafast.huyooo.com/middleware/cookie.html)（仓库内 `vafast-doc/docs/middleware/cookie.md`）。
