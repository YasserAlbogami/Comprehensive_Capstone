export interface ApiResponse<T> {
  data: T
  error?: string
}

class ApiClient {
  private baseUrl = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

  async get<T>(endpoint: string, params?: Record<string, string>) {
    const url = new URL(endpoint, this.baseUrl);
    console.log("[API CALL]", url.toString());  
    const response = await fetch(url.toString());
    const data = await response.json();
    return { data } as any;
  }

  async getAttacks(filters = {}) {
    return this.get("/attacks", filters as Record<string, string>);
  }
}
export const apiClient = new ApiClient();

