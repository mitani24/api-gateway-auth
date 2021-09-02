import {
  Handler,
  APIGatewayAuthorizerEvent,
  APIGatewayAuthorizerResult,
} from "aws-lambda";
import jwt from "jsonwebtoken";
import jwks from "jwks-rsa";

const AUTH0_AUDIENCE = process.env.AUTH0_AUDIENCE;
const AUTH0_ISSUER = process.env.AUTH0_ISSUER;

const verifyOption = {
  audience: AUTH0_AUDIENCE,
  issuer: AUTH0_ISSUER,
};

const client = jwks({
  jwksUri: `${AUTH0_ISSUER}.well-known/jwks.json`,
});

const getKey: jwt.GetPublicKeyOrSecret = async (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    callback(null, key.getPublicKey());
  });
};

const getToken = (authHeader?: string) => {
  if (!authHeader) return null;
  if (!authHeader.startsWith("Bearer ")) return null;
  return authHeader.substring(7);
};

const verifyToken = (token: string): Promise<jwt.JwtPayload> => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, getKey, verifyOption, (err, decoded) => {
      if (err) {
        reject(err);
      }
      resolve(decoded!);
    });
  });
};

// https://docs.aws.amazon.com/ja_jp/IAM/latest/UserGuide/reference_policies_elements.html
const generatePolicy = (
  principal: string,
  effect: "Allow" | "Deny",
  resource: string
): APIGatewayAuthorizerResult => {
  return {
    principalId: principal,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          // https://docs.aws.amazon.com/ja_jp/apigateway/latest/developerguide/api-gateway-control-access-using-iam-policies-to-invoke-api.html#api-gateway-iam-policy-action-format-for-executing-api
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resource,
        },
      ],
    },
  };
};

export const auth: Handler<
  APIGatewayAuthorizerEvent,
  APIGatewayAuthorizerResult
> = (event, context, callback) => {
  if (event.type !== "TOKEN") {
    console.log(`expected authorization type is TOKEN, got ${event.type}`);
    callback("Unauthorized");
    return;
  }

  const token = getToken(event.authorizationToken);
  if (!token) {
    console.log("authorization token must not bet null");
    callback("Unauthorized");
    return;
  }

  verifyToken(token)
    .then((decoded) => {
      if (!decoded.sub) {
        console.log("jwt payload must have a sub claim");
        callback("Unauthorized");
        return;
      }
      callback(null, generatePolicy(decoded.sub, "Allow", event.methodArn));
    })
    .catch((err) => {
      console.log(`failed to verify token. error: ${err}`);
      callback("Unauthorized");
    });
};
