// Orange Cloud OAuth 回调中转（与 apps/web/src/app/oauth/callback/route.ts 行为对齐）
// Cloudflare 只接受 https redirect_uri；此 Worker 把授权码 302 透传给 App 自定义 scheme。
// 不存 code、不换 Token、不验 state（验证在 App 端做，PKCE 保证安全）。
export default {
	async fetch(request) {
		const { searchParams } = new URL(request.url);
		const APP_CALLBACK = "orangecloud://oauth/callback";

		const code = searchParams.get("code");
		const state = searchParams.get("state");
		const error = searchParams.get("error");

		// Cloudflare 返回错误（用户拒绝授权等）
		if (error) {
			const errorDesc = searchParams.get("error_description") ?? error;
			return Response.redirect(
				`${APP_CALLBACK}?error=${encodeURIComponent(errorDesc)}`,
				302,
			);
		}

		// 缺少必要参数
		if (!code || !state) {
			return Response.redirect(`${APP_CALLBACK}?error=invalid_response`, 302);
		}

		const appCallbackUrl = new URL(APP_CALLBACK);
		appCallbackUrl.searchParams.set("code", code);
		appCallbackUrl.searchParams.set("state", state);

		return Response.redirect(appCallbackUrl.toString(), 302);
	},
};