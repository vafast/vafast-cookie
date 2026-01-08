# @vafast/cookie

Vafast Cookie 解析、签名与验证中间件。

## ✨ 特性

- 🍪 Cookie 解析中间件
- 🔐 HMAC 签名与验证（防篡改）
- 🛡️ 时间安全比较（防时序攻击）
- 🧰 CookieJar 响应辅助类

## 📦 安装

```bash
npm install @vafast/cookie
```

## 🚀 使用

### 基础 Cookie 解析

```typescript
import { Server, defineRoutes, createHandler } from 'vafast'
import { cookies } from '@vafast/cookie'

const routes = defineRoutes([
  {
    method: 'GET',
    path: '/profile',
    handler: createHandler({}, async ({ req }) => {
      const sessionId = req.cookies?.sessionId
      return { sessionId }
    })
  }
])

const app = new Server(routes)
app.use(cookies())
```

### 签名 Cookie

```typescript
import { signedCookies, createCookieJar } from '@vafast/cookie'

const SECRET = process.env.COOKIE_SECRET!

// 中间件会自动验证签名
app.use(signedCookies({ secret: SECRET }))

// 在处理函数中
createHandler({}, async ({ req }) => {
  // req.signedCookies 包含已验证的签名 Cookie
  const userId = req.signedCookies?.userId
  
  // req.cookies 包含普通 Cookie（或签名无效的 Cookie）
  const theme = req.cookies?.theme
  
  // 设置签名 Cookie
  const jar = createCookieJar(SECRET)
  jar.setSigned('userId', 'user123', {
    httpOnly: true,
    secure: true,
    maxAge: 60 * 60 * 24 * 7, // 7 天
    sameSite: 'Strict'
  })
  
  const response = new Response(JSON.stringify({ ok: true }))
  return jar.apply(response)
})
```

### 删除 Cookie

```typescript
const jar = createCookieJar()
jar.delete('session')

const response = jar.apply(new Response('Logged out'))
```

## 📚 API

### 中间件

#### `cookies()`

解析请求中的所有 Cookie 到 `req.cookies`。

#### `signedCookies(options)`

解析并验证签名 Cookie。

- 有效签名 → `req.signedCookies`
- 无效签名 / 普通 Cookie → `req.cookies`

| 选项 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `secret` | `string` | - | 签名密钥（必填） |
| `algorithm` | `string` | `'sha256'` | HMAC 算法 |

### 工具函数

#### `sign(value, secret, algorithm?)`

对值进行 HMAC 签名，返回 `value.signature` 格式。

#### `unsign(signedValue, secret, algorithm?)`

验证签名并返回原始值，失败返回 `null`。

#### `parseCookies(cookieHeader)`

解析 Cookie 字符串为对象。

#### `serializeCookie(name, value, options?)`

序列化为 `Set-Cookie` 头值。

### CookieJar

链式 API 设置响应 Cookie。

```typescript
const jar = createCookieJar(secret?)

jar
  .set('plain', 'value', options?)       // 普通 Cookie
  .setSigned('signed', 'value', options?) // 签名 Cookie（需要 secret）
  .delete('old', options?)                // 删除 Cookie
  .apply(response)                        // 应用到响应
```

### CookieOptions

```typescript
interface CookieOptions {
  expires?: Date | number  // 过期时间
  maxAge?: number          // 秒
  domain?: string
  path?: string            // 默认 '/'
  secure?: boolean         // 仅 HTTPS
  httpOnly?: boolean       // 默认 true
  sameSite?: 'Strict' | 'Lax' | 'None'
}
```

## 🔒 安全说明

1. **使用强密钥**: `secret` 应该是随机生成的长字符串
2. **环境变量存储**: 不要硬编码密钥
3. **HTTPS**: 生产环境建议开启 `secure: true`
4. **HttpOnly**: 默认开启，防止 XSS 窃取

## 📄 许可证

MIT

