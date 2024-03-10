import { jwtDecode } from 'jwt-decode';

const BUCKET_URL = "https://pub-a42514f5130e40f2b8e820fe4a1e96e3.r2.dev"

export interface Env {}

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
				const countryFlagUrl2 = `${BUCKET_URL}/${countryCode}.svg`
				const html2 = `<!DOCTYPE html>
							  <body>
							  <h1>Country Code: ${path}</h1>
						      <img src= "${countryFlagUrl2}" alt="Country Flag"/>
							  </body>
							`;
				return new Response(html2, {
					headers: {
						"content-type": "text/html;charset=UTF-8",
					},
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
							  <h1>Hello World</h1>
						      <p>${data.email} authenticated at ${getCurrentTimestamp()} from <a href="${countryFlagUrl}" target="_blank">${data.country}</a></p>.</p>
							  </body>
							`;
				return new Response(html, {
					headers: {
						"content-type": "text/html;charset=UTF-8",
					},
				});
			default:
				return new Response("page accessible to all");
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
