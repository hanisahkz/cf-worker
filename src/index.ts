import { jwtDecode } from 'jwt-decode';

export interface Env {
	FLAG_BUCKET: R2Bucket;
}

type CfJwt = {
	aud: Array<string>;
	email: string;
	exp: number;
	iat: number;
	nbf: number;
	iss: string;
	type: string;
	identity_none: string;
	sub: string;
	country: string;
};

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const headers = Object.fromEntries(request.headers);
		const urlParts: Array<string> = request.url.split('/');
		const path: string = urlParts.slice(-1).join();

		switch (path) {
			case "debug-secure": case "debug-open":
				return new Response(JSON.stringify(headers));
			// Note: List of country codes using ISO 3166-1 Alpha 2 format: https://www.iso.org/obp/ui/#search
			// TODO: Improve to handle unrecognized country code
			case "MY": case "SG": case "KR": case "US": 
				const countryCode = path.toLocaleLowerCase();
				const key = `${countryCode}.svg`;
				const flagObject = await env.FLAG_BUCKET.get(key);
				const bucketHeaders = new Headers();

				if (flagObject === null) {
					return new Response('Object Not Found', { status: 404 });
				}

				flagObject.writeHttpMetadata(bucketHeaders);
				bucketHeaders.set('etag', flagObject.httpEtag);

				return new Response(flagObject.body, {
					headers: bucketHeaders,
				});
			case "secure-jwt":
				const dataJwt = decodeCfJwt(headers['cookie']);
				return new Response(JSON.stringify(dataJwt));
			case "secure":
				const data = {
					email: headers['cf-access-authenticated-user-email'],
					country: headers['cf-ipcountry'],
				}
				const countryFlagUrl = `/secure/${data.country}`
				const html = `<!DOCTYPE html>
							  <body>
						      <p>${data.email} authenticated at ${getCurrentTimestamp()} from <a href="${countryFlagUrl}" target="_blank">${data.country}</a></p>.</p>
							  </body>
							`;
				return new Response(html, {
					headers: {
						"content-type": "text/html;charset=UTF-8",
					},
				});
			default:
				return new Response("Default restricted page");
		}
	},
};

// Note: For endpoint protected with Cloudflare Access, the jwt token is available via "CF_Authorization"
// contains info such as: email, country too.
const decodeCfJwt = (cookies: string) => {
	const cfAuthCookie = cookies.split(";").filter(a => a.includes("CF_Authorization")).join()
	const cfAuthToken = cfAuthCookie.split("=")[1];
	const decoded: CfJwt = jwtDecode(cfAuthToken);
	const { email, country } = decoded;
	return { email, country };
};

const getCurrentTimestamp = () => new Date().toISOString();
