import { AuthorizationError } from "./errors";
import { IncomingMessage } from "http";
import { decode, verify } from "jsonwebtoken";
import { SchemaDirectiveVisitor } from "graphql-tools";
import {
  DirectiveLocation,
  GraphQLDirective,
  GraphQLField,
  GraphQLList,
  GraphQLObjectType,
  GraphQLString,
} from "graphql";

// interface MyToken {
//   name: string;
//   exp: number;
//   Permissions?: string;
//   permissions?: string;
//   Scopes?: string;
//   scopes?: string;
//   Scope?: string;
//   scope?: string;
//   // whatever else is in the JWT.
// }

const verifyAndDecodeToken = ({ context }: any) => {
  const req =
    context instanceof IncomingMessage
      ? context
      : context.req || context.request;

  if (
    !req ||
    !req.headers ||
    (!req.headers.authorization && !req.headers.Authorization) ||
    (!req && !req.cookies && !req.cookies.token)
  ) {
    throw new AuthorizationError({ message: "No authorization token." });
  }

  const token =
    req.headers.authorization || req.headers.Authorization || req.cookies.token;
  try {
    const id_token = token.replace("Bearer ", "");
    const { JWT_SECRET, JWT_NO_VERIFY } = process.env;

    if (!JWT_SECRET && JWT_NO_VERIFY) {
      return decode(id_token);
    } else {
      return verify(id_token, JWT_SECRET as string, {
        algorithms: ["HS256", "RS256"],
      });
    }
  } catch (err) {
    if (err.name === "TokenExpiredError") {
      throw new AuthorizationError({
        message: "Your token is expired",
      });
    } else {
      throw new AuthorizationError({
        message: "You are not authorized for this resource",
      });
    }
  }
};

export class HasScopeDirective extends SchemaDirectiveVisitor {
  static getDirectiveDeclaration(_directiveName: string, _schema: any) {
    return new GraphQLDirective({
      name: "hasScope",
      locations: [DirectiveLocation.FIELD_DEFINITION, DirectiveLocation.OBJECT],
      args: {
        scopes: {
          type: new GraphQLList(GraphQLString),
          defaultValue: "none:read",
        },
      },
    });
  }

  // used for example, with Query and Mutation fields
  visitFieldDefinition(field: GraphQLField<any, any>) {
    const expectedScopes: string[] = this.args.scopes;
    const next = field.resolve;

    // wrap resolver with auth check
    field.resolve = function (result, args, context, info) {
      const decoded = verifyAndDecodeToken({ context });

      // Initialize an array to keep roles.
      const scopes: string[] = [];

      // If the env var is set push that key
      if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
        scopes.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
      }
      // push keys coded into the JWT
      const keys =
        decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
      for (const role of keys) {
        scopes.push(role);
      }

      if (expectedScopes.some((scope) => scopes.indexOf(scope) !== -1)) {
        return next && next(result, args, { ...context, user: decoded }, info);
      }

      throw new AuthorizationError({
        message: "You are not authorized for this resource",
      });
    };
  }

  visitObject(obj: GraphQLObjectType) {
    const fields = obj.getFields();
    const expectedScopes: string[] = this.args.scopes;

    Object.keys(fields).forEach((fieldName) => {
      const field = fields[fieldName];
      const next = field.resolve;
      field.resolve = function (result, args, context, info) {
        const decoded = verifyAndDecodeToken({ context });

        // const scopes = process.env.AUTH_DIRECTIVES_SCOPE_KEY
        //   ? decoded[process.env.AUTH_DIRECTIVES_SCOPE_KEY] || []
        //   : decoded["permissions"] ||
        //     decoded["Permissions"] ||
        //     decoded["Scopes"] ||
        //     decoded["scopes"] ||
        //     decoded["Scope"] ||
        //     decoded["scope"] ||
        //     [];

        // Initialize an array to keep roles.
        const scopes: string[] = [];

        // If the env var is set push that key
        if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
          scopes.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
        }
        // push keys coded into the JWT
        const keys =
          decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
        for (const role of keys) {
          scopes.push(role);
        }

        if (expectedScopes.some((role) => scopes.indexOf(role) !== -1)) {
          return (
            next && next(result, args, { ...context, user: decoded }, info)
          );
        }
        throw new AuthorizationError({
          message: "You are not authorized for this resource",
        });
      };
    });
  }
}

export class HasRoleDirective extends SchemaDirectiveVisitor {
  static getDirectiveDeclaration(_directiveName: string, schema: any) {
    return new GraphQLDirective({
      name: "hasRole",
      locations: [DirectiveLocation.FIELD_DEFINITION, DirectiveLocation.OBJECT],
      args: {
        roles: {
          type: new GraphQLList(schema.getType("Role")),
          defaultValue: "reader",
        },
      },
    });
  }

  visitFieldDefinition(field: GraphQLField<any, any>) {
    const expectedRoles: string[] = this.args.roles;
    const next = field.resolve;

    field.resolve = function (result, args, context, info) {
      const decoded = verifyAndDecodeToken({ context });

      // const roles = process.env.AUTH_DIRECTIVES_ROLE_KEY
      //   ? decoded[process.env.AUTH_DIRECTIVES_ROLE_KEY] || []
      //   : decoded["Roles"] ||
      //     decoded["roles"] ||
      //     decoded["Role"] ||
      //     decoded["role"] ||
      //     [];

      // Initialize an array to keep roles.
      const roles: string[] = [];

      // If the env var is set push that key
      if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
        roles.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
      }
      // push keys coded into the JWT
      const keys =
        decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
      for (const role of keys) {
        roles.push(role);
      }

      if (expectedRoles.some((role: any) => roles.indexOf(role) !== -1)) {
        return next && next(result, args, { ...context, user: decoded }, info);
      }

      throw new AuthorizationError({
        message: "You are not authorized for this resource",
      });
    };
  }

  visitObject(obj: GraphQLObjectType) {
    const fields = obj.getFields();
    const expectedRoles: string[] = this.args.roles;

    Object.keys(fields).forEach((fieldName) => {
      const field = fields[fieldName];
      const next = field.resolve;
      field.resolve = function (result, args, context, info) {
        const decoded = verifyAndDecodeToken({ context });

        // const roles = process.env.AUTH_DIRECTIVES_ROLE_KEY
        //   ? decoded[process.env.AUTH_DIRECTIVES_ROLE_KEY] || []
        //   : decoded["Roles"] ||
        //     decoded["roles"] ||
        //     decoded["Role"] ||
        //     decoded["role"] ||
        //     [];

        // Initialize an array to keep roles.
        const roles: string[] = [];

        // If the env var is set push that key
        if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
          roles.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
        }
        // push keys coded into the JWT
        const keys =
          decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
        for (const role of keys) {
          roles.push(role);
        }

        if (expectedRoles.some((role) => roles.indexOf(role) !== -1)) {
          return (
            next && next(result, args, { ...context, user: decoded }, info)
          );
        }
        throw new AuthorizationError({
          message: "You are not authorized for this resource",
        });
      };
    });
  }
}

export class IsAuthenticatedDirective extends SchemaDirectiveVisitor {
  static getDirectiveDeclaration(_directiveName: string, _schema: any) {
    return new GraphQLDirective({
      name: "isAuthenticated",
      locations: [DirectiveLocation.FIELD_DEFINITION, DirectiveLocation.OBJECT],
    });
  }

  visitObject(obj: GraphQLObjectType) {
    const fields = obj.getFields();

    Object.keys(fields).forEach((fieldName) => {
      const field = fields[fieldName];
      const next = field.resolve;

      field.resolve = function (result, args, context, info) {
        const decoded = verifyAndDecodeToken({ context }); // will throw error if not valid signed jwt
        return next && next(result, args, { ...context, user: decoded }, info);
      };
    });
  }

  visitFieldDefinition(field: GraphQLField<any, any>) {
    const next = field.resolve;

    field.resolve = function (result, args, context, info) {
      const decoded = verifyAndDecodeToken({ context });
      return next && next(result, args, { ...context, user: decoded }, info);
    };
  }
}
