import server from "./server";
import { auth } from "./auth";

export const graphqlHandler = server.createHandler();
export const authHandler = auth;
