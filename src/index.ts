/**
 * vafast-cookie
 * Cookie 解析、签名与验证中间件
 */

import { createHmac, timingSafeEqual } from 'node:crypto'
import { defineMiddleware } from 'vafast'

/** Cookie 选项 */
export interface CookieOptions {
  /** 过期时间（Date 对象或时间戳） */
  expires?: Date | number
  /** 最大存活时间（秒） */
  maxAge?: number
  /** 域名 */
  domain?: string
  /** 路径，默认 '/' */
  path?: string
  /** 是否仅 HTTPS，默认 false */
  secure?: boolean
  /** 是否仅 HTTP（禁止 JS 访问），默认 true */
  httpOnly?: boolean
  /** SameSite 策略 */
  sameSite?: 'Strict' | 'Lax' | 'None'
}

/** 签名 Cookie 中间件配置 */
export interface SignedCookiesOptions {
  /** 签名密钥（必填） */
  secret: string
  /** 签名算法，默认 'sha256' */
  algorithm?: string
}

/** 扩展 Request 类型 */
declare global {
  interface Request {
    cookies?: Record<string, string>
    signedCookies?: Record<string, string>
  }
}

/**
 * 解析 Cookie 字符串为对象
 */
export function parseCookies(cookieHeader: string | null): Record<string, string> {
  if (!cookieHeader) return {}
  
  const cookies: Record<string, string> = {}
  
  for (const pair of cookieHeader.split(';')) {
    const [key, ...valueParts] = pair.split('=')
    const trimmedKey = key?.trim()
    if (trimmedKey) {
      const value = valueParts.join('=').trim()
      cookies[trimmedKey] = decodeURIComponent(value)
    }
  }
  
  return cookies
}

/**
 * 序列化 Cookie 为 Set-Cookie 头值
 */
export function serializeCookie(
  name: string,
  value: string,
  options: CookieOptions = {}
): string {
  const parts = [`${encodeURIComponent(name)}=${encodeURIComponent(value)}`]
  
  if (options.maxAge !== undefined) {
    parts.push(`Max-Age=${options.maxAge}`)
  }
  
  if (options.expires) {
    const date = options.expires instanceof Date 
      ? options.expires 
      : new Date(options.expires)
    parts.push(`Expires=${date.toUTCString()}`)
  }
  
  if (options.domain) {
    parts.push(`Domain=${options.domain}`)
  }
  
  parts.push(`Path=${options.path ?? '/'}`)
  
  if (options.secure) {
    parts.push('Secure')
  }
  
  if (options.httpOnly !== false) {
    parts.push('HttpOnly')
  }
  
  if (options.sameSite) {
    parts.push(`SameSite=${options.sameSite}`)
  }
  
  return parts.join('; ')
}

/**
 * 对值进行 HMAC 签名
 */
export function sign(value: string, secret: string, algorithm = 'sha256'): string {
  const signature = createHmac(algorithm, secret)
    .update(value)
    .digest('base64url')
  return `${value}.${signature}`
}

/**
 * 验证并提取签名值
 * 返回原始值或 null（验证失败）
 */
export function unsign(signedValue: string, secret: string, algorithm = 'sha256'): string | null {
  const lastDotIndex = signedValue.lastIndexOf('.')
  if (lastDotIndex === -1) return null
  
  const value = signedValue.slice(0, lastDotIndex)
  const signature = signedValue.slice(lastDotIndex + 1)
  
  const expectedSignature = createHmac(algorithm, secret)
    .update(value)
    .digest('base64url')
  
  // 使用时间安全比较防止时序攻击
  const sigBuffer = Buffer.from(signature)
  const expectedBuffer = Buffer.from(expectedSignature)
  
  if (sigBuffer.length !== expectedBuffer.length) return null
  
  if (!timingSafeEqual(sigBuffer, expectedBuffer)) return null
  
  return value
}

/**
 * 创建 Cookie 解析中间件
 * 
 * @example
 * ```typescript
 * import { cookies } from '@vafast/cookie'
 * 
 * app.use(cookies())
 * 
 * // 在处理函数中使用
 * defineRoute({
 *   method: 'GET',
 *   path: '/',
 *   handler: ({ req }) => {
 *     const sessionId = req.cookies?.sessionId
 *     return { sessionId }
 *   }
 * })
 * ```
 */
export function cookies() {
  return defineMiddleware<{ cookies: Record<string, string> }>(async (req, next) => {
    const cookieHeader = req.headers.get('Cookie')
    const parsedCookies = parseCookies(cookieHeader)
    ;(req as Request & { cookies: Record<string, string> }).cookies = parsedCookies
    
    return next({ cookies: parsedCookies })
  })
}

/**
 * 创建签名 Cookie 中间件
 * 
 * @example
 * ```typescript
 * import { signedCookies } from '@vafast/cookie'
 * 
 * app.use(signedCookies({ secret: 'your-secret-key' }))
 * 
 * // 在处理函数中使用
 * defineRoute({
 *   method: 'GET',
 *   path: '/',
 *   handler: ({ signedCookies }) => {
 *     // 已验证的签名 Cookie
 *     const userId = signedCookies?.userId
 *     return { userId }
 *   }
 * })
 * ```
 */
export function signedCookies(options: SignedCookiesOptions) {
  const { secret, algorithm = 'sha256' } = options
  
  return defineMiddleware<{ cookies: Record<string, string>; signedCookies: Record<string, string> }>(async (req, next) => {
    const cookieHeader = req.headers.get('Cookie')
    const allCookies = parseCookies(cookieHeader)
    
    const plainCookies: Record<string, string> = {}
    const verified: Record<string, string> = {}
    
    for (const [key, value] of Object.entries(allCookies)) {
      // 尝试验证签名
      const unsigned = unsign(value, secret, algorithm)
      if (unsigned !== null) {
        verified[key] = unsigned
      } else {
        plainCookies[key] = value
      }
    }
    
    ;(req as Request & { cookies: Record<string, string> }).cookies = plainCookies
    ;(req as Request & { signedCookies: Record<string, string> }).signedCookies = verified
    
    return next({ cookies: plainCookies, signedCookies: verified })
  })
}

/**
 * Cookie 辅助类，用于在响应中设置 Cookie
 */
export class CookieJar {
  private cookies: string[] = []
  private secret?: string
  private algorithm: string
  
  constructor(secret?: string, algorithm = 'sha256') {
    this.secret = secret
    this.algorithm = algorithm
  }
  
  /**
   * 设置普通 Cookie
   */
  set(name: string, value: string, options?: CookieOptions): this {
    this.cookies.push(serializeCookie(name, value, options))
    return this
  }
  
  /**
   * 设置签名 Cookie
   */
  setSigned(name: string, value: string, options?: CookieOptions): this {
    if (!this.secret) {
      throw new Error('Secret is required for signed cookies')
    }
    const signedValue = sign(value, this.secret, this.algorithm)
    this.cookies.push(serializeCookie(name, signedValue, options))
    return this
  }
  
  /**
   * 删除 Cookie
   */
  delete(name: string, options?: Pick<CookieOptions, 'domain' | 'path'>): this {
    this.cookies.push(serializeCookie(name, '', {
      ...options,
      maxAge: 0,
      expires: new Date(0),
    }))
    return this
  }
  
  /**
   * 将 Cookie 应用到响应
   */
  apply(response: Response): Response {
    if (this.cookies.length === 0) return response
    
    const newHeaders = new Headers(response.headers)
    for (const cookie of this.cookies) {
      newHeaders.append('Set-Cookie', cookie)
    }
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newHeaders,
    })
  }
}

/**
 * 创建 Cookie Jar
 */
export function createCookieJar(secret?: string, algorithm?: string): CookieJar {
  return new CookieJar(secret, algorithm)
}

export default {
  cookies,
  signedCookies,
  parseCookies,
  serializeCookie,
  sign,
  unsign,
  createCookieJar,
  CookieJar,
}
