import { describe, it, expect, vi } from 'vitest'
import {
  parseCookies,
  serializeCookie,
  sign,
  unsign,
  cookies,
  signedCookies,
  CookieJar,
  createCookieJar,
} from '../src'

describe('parseCookies', () => {
  it('should parse cookie string', () => {
    const result = parseCookies('foo=bar; baz=qux')
    expect(result).toEqual({ foo: 'bar', baz: 'qux' })
  })

  it('should handle empty string', () => {
    expect(parseCookies('')).toEqual({})
    expect(parseCookies(null)).toEqual({})
  })

  it('should decode URI encoded values', () => {
    const result = parseCookies('name=%E4%B8%AD%E6%96%87')
    expect(result).toEqual({ name: '中文' })
  })

  it('should handle values with equals sign', () => {
    const result = parseCookies('token=abc=def=ghi')
    expect(result).toEqual({ token: 'abc=def=ghi' })
  })
})

describe('serializeCookie', () => {
  it('should serialize basic cookie', () => {
    const result = serializeCookie('foo', 'bar')
    expect(result).toBe('foo=bar; Path=/; HttpOnly')
  })

  it('should serialize with all options', () => {
    const expires = new Date('2025-01-01')
    const result = serializeCookie('foo', 'bar', {
      expires,
      maxAge: 3600,
      domain: 'example.com',
      path: '/api',
      secure: true,
      httpOnly: true,
      sameSite: 'Strict',
    })
    
    expect(result).toContain('foo=bar')
    expect(result).toContain('Max-Age=3600')
    expect(result).toContain('Expires=')
    expect(result).toContain('Domain=example.com')
    expect(result).toContain('Path=/api')
    expect(result).toContain('Secure')
    expect(result).toContain('HttpOnly')
    expect(result).toContain('SameSite=Strict')
  })

  it('should allow disabling HttpOnly', () => {
    const result = serializeCookie('foo', 'bar', { httpOnly: false })
    expect(result).not.toContain('HttpOnly')
  })
})

describe('sign and unsign', () => {
  const secret = 'test-secret'

  it('should sign and unsign value', () => {
    const signed = sign('hello', secret)
    expect(signed).toContain('hello.')
    
    const unsigned = unsign(signed, secret)
    expect(unsigned).toBe('hello')
  })

  it('should return null for invalid signature', () => {
    const result = unsign('hello.invalid-signature', secret)
    expect(result).toBeNull()
  })

  it('should return null for value without signature', () => {
    const result = unsign('hello', secret)
    expect(result).toBeNull()
  })

  it('should return null for wrong secret', () => {
    const signed = sign('hello', secret)
    const result = unsign(signed, 'wrong-secret')
    expect(result).toBeNull()
  })

  it('should handle values with dots', () => {
    const signed = sign('hello.world', secret)
    const unsigned = unsign(signed, secret)
    expect(unsigned).toBe('hello.world')
  })
})

describe('cookies middleware', () => {
  it('should parse cookies from request', async () => {
    const middleware = cookies()
    const req = new Request('http://localhost/test', {
      headers: { Cookie: 'session=abc123; user=john' },
    })
    
    const next = vi.fn().mockResolvedValue(new Response('OK'))
    
    await middleware(req, next)
    
    expect((req as any).cookies).toEqual({
      session: 'abc123',
      user: 'john',
    })
  })
})

describe('signedCookies middleware', () => {
  const secret = 'test-secret'

  it('should verify signed cookies', async () => {
    const middleware = signedCookies({ secret })
    
    const signedValue = sign('user123', secret)
    const req = new Request('http://localhost/test', {
      headers: { Cookie: `userId=${signedValue}; plain=value` },
    })
    
    const next = vi.fn().mockResolvedValue(new Response('OK'))
    
    await middleware(req, next)
    
    expect((req as any).signedCookies).toEqual({ userId: 'user123' })
    expect((req as any).cookies).toEqual({ plain: 'value' })
  })

  it('should ignore invalid signatures', async () => {
    const middleware = signedCookies({ secret })
    
    const req = new Request('http://localhost/test', {
      headers: { Cookie: 'userId=tampered.invalid' },
    })
    
    const next = vi.fn().mockResolvedValue(new Response('OK'))
    
    await middleware(req, next)
    
    expect((req as any).signedCookies).toEqual({})
    expect((req as any).cookies).toEqual({ userId: 'tampered.invalid' })
  })
})

describe('CookieJar', () => {
  it('should set cookies', () => {
    const jar = createCookieJar()
    jar.set('foo', 'bar')
    
    const response = jar.apply(new Response('OK'))
    
    expect(response.headers.get('Set-Cookie')).toContain('foo=bar')
  })

  it('should set signed cookies', () => {
    const secret = 'test-secret'
    const jar = createCookieJar(secret)
    jar.setSigned('session', 'user123')
    
    const response = jar.apply(new Response('OK'))
    const cookie = response.headers.get('Set-Cookie')
    
    expect(cookie).toContain('session=user123.')
    // 验证签名
    const value = cookie?.split('=')[1]?.split(';')[0]
    expect(unsign(value!, secret)).toBe('user123')
  })

  it('should throw if signing without secret', () => {
    const jar = createCookieJar()
    expect(() => jar.setSigned('foo', 'bar')).toThrow('Secret is required')
  })

  it('should delete cookies', () => {
    const jar = createCookieJar()
    jar.delete('session')
    
    const response = jar.apply(new Response('OK'))
    const cookie = response.headers.get('Set-Cookie')
    
    expect(cookie).toContain('session=')
    expect(cookie).toContain('Max-Age=0')
  })

  it('should set multiple cookies', () => {
    const jar = createCookieJar()
    jar.set('foo', 'bar').set('baz', 'qux')
    
    const response = jar.apply(new Response('OK'))
    const cookies = response.headers.getSetCookie()
    
    expect(cookies).toHaveLength(2)
  })

  it('should support chaining', () => {
    const jar = createCookieJar('secret')
    
    const result = jar
      .set('plain', 'value')
      .setSigned('signed', 'secure')
      .delete('old')
    
    expect(result).toBe(jar)
  })
})

