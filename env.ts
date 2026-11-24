import { config as loadDotEnv } from "dotenv";
import { createEnv } from "@t3-oss/env-core";
import * as z from "zod";

const dotenvResult = loadDotEnv();
if (
  dotenvResult.error &&
  !("code" in dotenvResult.error && dotenvResult.error.code === "ENOENT")
) {
  throw dotenvResult.error;
}

export const env = createEnv({
  server: {
    AUTH_SERVICE_URL: z
      .url()
      .default("https://auth.outboundendurance.com"),
  },
  runtimeEnv: process.env,
  emptyStringAsUndefined: true,
});
