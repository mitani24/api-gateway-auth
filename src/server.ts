import fs from "fs";
import path from "path";
import { ApolloServer, gql } from "apollo-server-lambda";
import TrackAPI from "./datasources/track-api";
import resolvers from "./resolvers";

const typeDefs = fs
  .readFileSync(path.join(__dirname, "../schema.graphql"))
  .toString();

const server = new ApolloServer({
  typeDefs: gql`
    ${typeDefs}
  `,
  dataSources() {
    return { trackAPI: new TrackAPI() };
  },
  resolvers,
});

export default server;
