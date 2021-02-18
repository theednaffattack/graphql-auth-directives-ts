"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IsAuthenticatedDirective = exports.HasRoleDirective = exports.HasScopeDirective = void 0;
const errors_1 = require("./errors");
const http_1 = require("http");
const jsonwebtoken_1 = require("jsonwebtoken");
const graphql_tools_1 = require("graphql-tools");
const graphql_1 = require("graphql");
const verifyAndDecodeToken = ({ context }) => {
    const req = context instanceof http_1.IncomingMessage
        ? context
        : context.req || context.request;
    if (!req ||
        !req.headers ||
        (!req.headers.authorization && !req.headers.Authorization) ||
        (!req && !req.cookies && !req.cookies.token)) {
        throw new errors_1.AuthorizationError({ message: "No authorization token." });
    }
    const token = req.headers.authorization || req.headers.Authorization || req.cookies.token;
    try {
        const id_token = token.replace("Bearer ", "");
        const { JWT_SECRET, JWT_NO_VERIFY } = process.env;
        if (!JWT_SECRET && JWT_NO_VERIFY) {
            return jsonwebtoken_1.decode(id_token);
        }
        else {
            return jsonwebtoken_1.verify(id_token, JWT_SECRET, {
                algorithms: ["HS256", "RS256"],
            });
        }
    }
    catch (err) {
        if (err.name === "TokenExpiredError") {
            throw new errors_1.AuthorizationError({
                message: "Your token is expired",
            });
        }
        else {
            throw new errors_1.AuthorizationError({
                message: "You are not authorized for this resource",
            });
        }
    }
};
class HasScopeDirective extends graphql_tools_1.SchemaDirectiveVisitor {
    static getDirectiveDeclaration(_directiveName, _schema) {
        return new graphql_1.GraphQLDirective({
            name: "hasScope",
            locations: [graphql_1.DirectiveLocation.FIELD_DEFINITION, graphql_1.DirectiveLocation.OBJECT],
            args: {
                scopes: {
                    type: new graphql_1.GraphQLList(graphql_1.GraphQLString),
                    defaultValue: "none:read",
                },
            },
        });
    }
    visitFieldDefinition(field) {
        const expectedScopes = this.args.scopes;
        const next = field.resolve;
        field.resolve = function (result, args, context, info) {
            const decoded = verifyAndDecodeToken({ context });
            const scopes = [];
            if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
                scopes.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
            }
            const keys = decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
            for (const role of keys) {
                scopes.push(role);
            }
            if (expectedScopes.some((scope) => scopes.indexOf(scope) !== -1)) {
                return next && next(result, args, Object.assign(Object.assign({}, context), { user: decoded }), info);
            }
            throw new errors_1.AuthorizationError({
                message: "You are not authorized for this resource",
            });
        };
    }
    visitObject(obj) {
        const fields = obj.getFields();
        const expectedScopes = this.args.scopes;
        Object.keys(fields).forEach((fieldName) => {
            const field = fields[fieldName];
            const next = field.resolve;
            field.resolve = function (result, args, context, info) {
                const decoded = verifyAndDecodeToken({ context });
                const scopes = [];
                if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
                    scopes.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
                }
                const keys = decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
                for (const role of keys) {
                    scopes.push(role);
                }
                if (expectedScopes.some((role) => scopes.indexOf(role) !== -1)) {
                    return (next && next(result, args, Object.assign(Object.assign({}, context), { user: decoded }), info));
                }
                throw new errors_1.AuthorizationError({
                    message: "You are not authorized for this resource",
                });
            };
        });
    }
}
exports.HasScopeDirective = HasScopeDirective;
class HasRoleDirective extends graphql_tools_1.SchemaDirectiveVisitor {
    static getDirectiveDeclaration(_directiveName, schema) {
        return new graphql_1.GraphQLDirective({
            name: "hasRole",
            locations: [graphql_1.DirectiveLocation.FIELD_DEFINITION, graphql_1.DirectiveLocation.OBJECT],
            args: {
                roles: {
                    type: new graphql_1.GraphQLList(schema.getType("Role")),
                    defaultValue: "reader",
                },
            },
        });
    }
    visitFieldDefinition(field) {
        const expectedRoles = this.args.roles;
        const next = field.resolve;
        field.resolve = function (result, args, context, info) {
            const decoded = verifyAndDecodeToken({ context });
            const roles = [];
            if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
                roles.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
            }
            const keys = decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
            for (const role of keys) {
                roles.push(role);
            }
            if (expectedRoles.some((role) => roles.indexOf(role) !== -1)) {
                return next && next(result, args, Object.assign(Object.assign({}, context), { user: decoded }), info);
            }
            throw new errors_1.AuthorizationError({
                message: "You are not authorized for this resource",
            });
        };
    }
    visitObject(obj) {
        const fields = obj.getFields();
        const expectedRoles = this.args.roles;
        Object.keys(fields).forEach((fieldName) => {
            const field = fields[fieldName];
            const next = field.resolve;
            field.resolve = function (result, args, context, info) {
                const decoded = verifyAndDecodeToken({ context });
                const roles = [];
                if (process.env.AUTH_DIRECTIVES_ROLE_KEY) {
                    roles.push(process.env.AUTH_DIRECTIVES_ROLE_KEY);
                }
                const keys = decoded && typeof decoded === "object" ? Object.keys(decoded) : [];
                for (const role of keys) {
                    roles.push(role);
                }
                if (expectedRoles.some((role) => roles.indexOf(role) !== -1)) {
                    return (next && next(result, args, Object.assign(Object.assign({}, context), { user: decoded }), info));
                }
                throw new errors_1.AuthorizationError({
                    message: "You are not authorized for this resource",
                });
            };
        });
    }
}
exports.HasRoleDirective = HasRoleDirective;
class IsAuthenticatedDirective extends graphql_tools_1.SchemaDirectiveVisitor {
    static getDirectiveDeclaration(_directiveName, _schema) {
        return new graphql_1.GraphQLDirective({
            name: "isAuthenticated",
            locations: [graphql_1.DirectiveLocation.FIELD_DEFINITION, graphql_1.DirectiveLocation.OBJECT],
        });
    }
    visitObject(obj) {
        const fields = obj.getFields();
        Object.keys(fields).forEach((fieldName) => {
            const field = fields[fieldName];
            const next = field.resolve;
            field.resolve = function (result, args, context, info) {
                const decoded = verifyAndDecodeToken({ context });
                return next && next(result, args, Object.assign(Object.assign({}, context), { user: decoded }), info);
            };
        });
    }
    visitFieldDefinition(field) {
        const next = field.resolve;
        field.resolve = function (result, args, context, info) {
            const decoded = verifyAndDecodeToken({ context });
            return next && next(result, args, Object.assign(Object.assign({}, context), { user: decoded }), info);
        };
    }
}
exports.IsAuthenticatedDirective = IsAuthenticatedDirective;
//# sourceMappingURL=index.js.map