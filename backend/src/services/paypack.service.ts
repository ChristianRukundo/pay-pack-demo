// backend/src/services/paypack.service.ts
import axios, { AxiosInstance } from "axios";
import crypto from "crypto";

interface CashinParams {
  number: string;
  amount: number;
}
interface CashinResponse {
  ref: string;
  status: string;
  amount: number;
  provider: string;
  kind: "CASHIN";
  created_at: string;
}

class PaypackService {
  private axiosInstance: AxiosInstance;
  private accessToken: string | null = null;
  private tokenExpiresAt: Date | null = null;

  constructor(private clientId: string, private clientSecret: string) {
    this.axiosInstance = axios.create({
      baseURL: "https://payments.paypack.rw/api",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
    });
  }

  private async getValidAccessToken(): Promise<string> {
    if (
      this.accessToken &&
      this.tokenExpiresAt &&
      new Date() < this.tokenExpiresAt
    ) {
      return this.accessToken;
    }
    console.log("Authenticating with Paypack...");
    const response = await this.axiosInstance.post("/auth/agents/authorize", {
      client_id: this.clientId,
      client_secret: this.clientSecret,
    });
    this.accessToken = response.data.access;
    this.tokenExpiresAt = new Date(response.data.expires * 1000);
    return this.accessToken;
  }

  public async cashin(params: CashinParams): Promise<CashinResponse> {
    const token = await this.getValidAccessToken();
    console.log("Initiating cashin for:", params.number);
    const response = await this.axiosInstance.post(
      "/transactions/cashin",
      params,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "X-Webhook-Mode": "production",
        },
      }
    );
    return response.data;
  }

  public verifyWebhookSignature(
    signature: string | undefined,
    rawBody: Buffer
  ): boolean {
    if (!signature) throw new Error("Missing webhook signature.");
    const expectedSignature = crypto
      .createHmac("sha256", process.env.PAYPACK_WEBHOOK_SECRET!)
      .update(rawBody)
      .digest("base64");
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  }
}

export const paypackService = new PaypackService(
  process.env.PAYPACK_CLIENT_ID!,
  process.env.PAYPACK_CLIENT_SECRET!
);
