import axios, { AxiosError } from "axios";
import type { APIGatewayProxyHandler } from "aws-lambda";
import AES from "crypto-js/aes";
import encutf8 from "crypto-js/enc-utf8";
import { nanoid } from "nanoid";
import { users } from "@clerk/clerk-sdk-node";

const API_BASE_URL = "https://otter.ai/forward/api/v1";
const CSRF_COOKIE_NAME = "csrftoken";

export type OtterSpeech = {
  speech_id: string;
  title: string;
  created_at: number;
  summary: string;
  otid: string;
  id: string;
  process_finished: boolean;
};
export type OtterSpeechInfo = {
  speech_id: string;
  title: string;
  created_at: number;
  summary: string;
  otid: string;
  id: string;
  process_finished: boolean;
  transcripts: {
    transcript: string;
    start_offset: number;
    end_offset: number;
    speaker_id: string;
  }[];
  speakers: { speaker_id: string; speaker_name: string; id: string }[];
};

const getCookieValueAndHeader = (
  cookieHeader?: string,
  cookieName?: string
) => {
  if (!cookieHeader || !cookieName)
    return { cookieHeader: "", cookieValue: "" };
  const match = cookieHeader.match(new RegExp(`${cookieName}=(?<value>.*?);`));
  if (!match) return { cookieHeader: "", cookieValue: "" };
  return { cookieValue: match[1], cookieHeader: match[0] };
};
class OtterApi {
  private options: { email: string; password: string };
  private user: { id?: string };
  constructor(options: { email: string; password: string }) {
    this.options = options;
    this.user = {};
  }

  init = async () => {
    await this.login();
  };

  login = async () => {
    const { email, password } = this.options;

    if (!email || !password) {
      throw new Error(
        "Email and/or password were not given. Can't perform authentication to otter.ai"
      );
    }
    const csrfResponse = await axios({
      method: "GET",
      url: `${API_BASE_URL}/login_csrf`,
    });
    const { cookieValue: csrfToken, cookieHeader: csrfCookie } =
      getCookieValueAndHeader(
        csrfResponse.headers["set-cookie"]?.[0],
        CSRF_COOKIE_NAME
      );

    const response = await axios({
      method: "GET",
      url: `${API_BASE_URL}/login`,
      params: {
        username: email,
      },
      headers: {
        authorization: `Basic ${Buffer.from(`${email}:${password}`).toString(
          "base64"
        )}`,
        "x-csrftoken": csrfToken,
        cookie: csrfCookie,
      },
      withCredentials: true,
    }).catch(() => {
      return Promise.reject(
        new Error(
          "Failed to log in to otter. Please make sure your Otter password was entered correctly into Roam."
        )
      );
    });

    const cookieHeader = (response.headers["set-cookie"] || [])
      .map((s: string) => `${s}`)
      .join("; ");

    this.user = response.data.user;

    axios.defaults.headers.common.cookie = cookieHeader;

    console.log("Successfuly logged in to Otter.ai");

    return response;
  };

  getSpeeches = async (
    params: string
  ): Promise<{
    speeches: OtterSpeech[];
    end_of_list: boolean;
    last_load_ts: number;
    last_modified_at: number;
  }> => {
    const { data } = await axios({
      method: "GET",
      url: `${API_BASE_URL}/speeches?${params}`,
      params: {
        userid: this.user.id,
      },
    });

    return data as {
      speeches: OtterSpeech[];
      end_of_list: boolean;
      last_load_ts: number;
      last_modified_at: number;
    };
  };

  getSpeech = async (speech_id: string): Promise<OtterSpeechInfo> => {
    const { data } = await axios({
      method: "GET",
      url: `${API_BASE_URL}/speech`,
      params: {
        speech_id,
        userid: this.user.id,
      },
    });

    return data.speech;
  };
}

const headers = {
  "Access-Control-Allow-Origin": "https://roamresearch.com",
  "Access-Control-Allow-Methods": "POST",
  "Access-Control-Allow-Credentials": true,
};

const catchError = (e: AxiosError) => {
  console.error(e.response?.data || e.message);
  const err = e.response?.data as Record<string, string>;
  return {
    headers,
    statusCode: 500,
    body: "message" in err ? err.message : e.response?.data || e.message,
  };
};

const transform = (s: OtterSpeech) => ({
  title: s.title,
  id: s.speech_id,
  createdDate: s.created_at,
  summary: s.summary,
  link: `https://otter.ai/u/${s.otid}`,
  isProcessed: s.process_finished,
});

const getApi = async ({
  email,
  password: inputPassword,
  token,
}: {
  email: string;
  password: string;
  token: string;
}) => {
  const results = await users.getUserList({ emailAddress: [email] });
  if (!results.length) return undefined;
  const user = results[0].privateMetadata.roamjsMetadata as {
    rawToken: string;
    otter: {
      key: string;
    };
  };
  const [, authToken] = Buffer.from(token.replace(/^Bearer /, ""), "base64")
    .toString("utf8")
    .split(":");
  if (user.rawToken !== authToken) return undefined;
  const password = AES.decrypt(inputPassword, user.otter.key).toString(encutf8);
  return new OtterApi({ email, password });
};

export const handler: APIGatewayProxyHandler = async (event) => {
  const { email, password, operation, params } = JSON.parse(event.body || "{}");
  const token =
    event.headers.Authorization || event.headers.authorization || "";
  if (operation === "ENCRYPT_PASSWORD") {
    const results = await users.getUserList({ emailAddress: [email] });
    const user = !results.length
      ? await Promise.resolve([nanoid(), nanoid(), nanoid()]).then(
          ([tempPassword, rawToken, otterKey]) =>
            users.createUser({
              emailAddress: [email],
              password: tempPassword,
              privateMetadata: {
                tempPassword,
                roamjsMetadata: {
                  rawToken,
                  otter: {
                    key: otterKey,
                  },
                },
              },
            })
        )
      : results[0];

    const roamjsData = user.privateMetadata.roamjsMetadata as {
      otter: { key: string };
      rawToken: string;
    };
    const encryptionSecret =
      roamjsData?.otter?.key ||
      (await Promise.resolve(nanoid()).then((key) =>
        users
          .updateUser(user.id, {
            privateMetadata: {
              ...user.privateMetadata,
              roamjsMetadata: {
                ...roamjsData,
                otter: {
                  key,
                },
              },
            },
          })
          .then(() => key)
      ));
    const rawToken =
      roamjsData?.rawToken ||
      (await Promise.resolve(nanoid()).then((key) =>
        users
          .updateUser(user.id, {
            privateMetadata: {
              ...user.privateMetadata,
              roamjsMetadata: {
                ...roamjsData,
                rawToken: key,
              },
            },
          })
          .then(() => key)
      ));
    const output = AES.encrypt(password, encryptionSecret).toString();
    return {
      statusCode: 200,
      body: JSON.stringify({ output, token: rawToken }),
      headers,
    };
  } else if (operation === "GET_SPEECHES") {
    const otterApi = await getApi({ email, password, token });
    if (!otterApi) {
      return {
        statusCode: 401,
        body: "Be sure to encrypt your password first in Roam Depot Settings before importing",
        headers,
      };
    }
    await otterApi.init();
    const pageSize = params?.pageSize || 10;
    const queryParams =
      `page_size=${pageSize}` +
      (params?.lastLoad && params?.lastModified
        ? `&modified_after=${params.lastModified}&last_load_ts=${params.lastLoad}`
        : "");
    const { speeches, last_load_ts, last_modified_at, end_of_list } =
      await otterApi.getSpeeches(queryParams);
    return {
      statusCode: 200,
      body: JSON.stringify({
        speeches: speeches.map(transform),
        lastLoad: last_load_ts,
        lastModified: last_modified_at,
        isEnd: end_of_list,
      }),
      headers,
    };
  } else if (operation === "GET_SPEECH") {
    const otterApi = await getApi({ email, password, token });
    if (!otterApi) {
      return {
        statusCode: 401,
        body: "Be sure to encrypt your password first in Roam Depot Settings before importing",
        headers,
      };
    }
    const speech = await otterApi
      .init()
      .then(() => otterApi.getSpeech(params.id));
    return {
      statusCode: 200,
      body: JSON.stringify({
        transcripts: speech.transcripts.map((t) => ({
          text: t.transcript,
          start: t.start_offset,
          end: t.end_offset,
          speaker:
            speech.speakers.find((s) => s.id === t.speaker_id)?.speaker_name ||
            "Unknown",
        })),
        ...transform(speech),
      }),
      headers,
    };
  } else {
    return {
      statusCode: 400,
      body: `Unsupported operation ${operation}`,
      headers: {
        "Access-Control-Allow-Origin": "https://roamresearch.com",
        "Access-Control-Allow-Methods": "POST",
        "Access-Control-Allow-Credentials": true,
      },
    };
  }
};
