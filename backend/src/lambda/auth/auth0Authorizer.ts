import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'
// import { decode } from 'jsonwebtoken'
import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
// import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

import * as middy from 'middy';
// import { secretsManager } from 'middy/middlewares';

const logger = createLogger('auth')

const cert = `-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJCWPs65IZxuKPMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMTFmRldi1mNGI1eXZ0ai5hdXRoMC5jb20wHhcNMjAwNDExMTIwMjM5WhcNMzMx
MjE5MTIwMjM5WjAhMR8wHQYDVQQDExZkZXYtZjRiNXl2dGouYXV0aDAuY29tMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuZ9HcrCXyqH3LAPZj1+wAcQg
9tg3I8eOi7WzGT6BSuGAJrXfy3EcyKYzfhZB6E1JcCdHIQTnI+kXkurYZtKjJwHw
EiFW3qKdPg7dIo5U4SG0Pdl74+y4r+1kwzzrTBICej2zUZC+dzHRAq4wbHXoYd/J
97viHabzdRrsHg7WgHiMq0KBp/dg46SSh2riC1Azk60v6X9bl+jtmij+2duR52qa
wKTSS2PMv25xtjdVivA4/hXluTNMaevV0bWI6NiwtSPfEuaafyY9ww2/WiBb/u59
WBjlvOmKVO9JioFAfeSXEZ1v5rC9Fq+yLkoDVwbjMuY6WVJ4wNhCCKY3SLUgSwID
AQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTbJ/YQoV7SK1R84Q9J
BRWCPkOGtjAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEBAEqRnC/C
9F14/rtHp8yhwfpsZEbk9X15q+3vqkES7HtTpGVgbqbVWR6q88KxW4BhaxbwI6S8
mQf1hvJIzx6CPhljmE85HRxD0GMS5XZG3x2eXIDODfICGxSFz2zSvpZP7RwIFPge
bTertGGPv7F2ZTL9X2bsw1h+EsMSrWbgqYh+s3UArhNF2vnUYVkdakvxh2XqwWuK
q5VUKCxFSbLyQKblj4Q7h65osaPcAQs7ZhCgu3IiUb/KYsqi5SjL28LVr6Y21uU+
cahx6L2b7eye7yhkZ4FJGt5WJzyQgvYRP/sO5Z52UFqTEKD7LkPyPEDdYV+vTNp1
qsJ5wilEAvsKYpk=
-----END CERTIFICATE-----`

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = '...'

export const handler = middy(async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
})

// const authSecret = process.env.AUTH_0_SECRET

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token,cert, {algorithms: ['RS256']}) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
