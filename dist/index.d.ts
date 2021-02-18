import { SchemaDirectiveVisitor } from "graphql-tools";
import { GraphQLDirective, GraphQLField, GraphQLObjectType } from "graphql";
export declare class HasScopeDirective extends SchemaDirectiveVisitor {
    static getDirectiveDeclaration(_directiveName: string, _schema: any): GraphQLDirective;
    visitFieldDefinition(field: GraphQLField<any, any>): void;
    visitObject(obj: GraphQLObjectType): void;
}
export declare class HasRoleDirective extends SchemaDirectiveVisitor {
    static getDirectiveDeclaration(_directiveName: string, schema: any): GraphQLDirective;
    visitFieldDefinition(field: GraphQLField<any, any>): void;
    visitObject(obj: GraphQLObjectType): void;
}
export declare class IsAuthenticatedDirective extends SchemaDirectiveVisitor {
    static getDirectiveDeclaration(_directiveName: string, _schema: any): GraphQLDirective;
    visitObject(obj: GraphQLObjectType): void;
    visitFieldDefinition(field: GraphQLField<any, any>): void;
}
//# sourceMappingURL=index.d.ts.map