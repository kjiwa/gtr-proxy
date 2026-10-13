import js from "@eslint/js";
import prettier from "eslint-config-prettier";
import tseslint from "typescript-eslint";

export default tseslint.config({ ignores: ["dist", "worker-configuration.d.ts"] }, js.configs.recommended, tseslint.configs.recommended, prettier);
