import axios from 'axios'
import type { TripFormData, TripPlanResponse } from '@/types'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/').trim()

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 300000, // 5分钟超时（LLM慢响应场景）
  headers: {
    'Content-Type': 'application/json'
  }
})

// 请求拦截器
apiClient.interceptors.request.use(
  (config) => {
    console.log('发送请求:', config.method?.toUpperCase(), config.url)
    return config
  },
  (error) => {
    console.error('请求错误:', error)
    return Promise.reject(error)
  }
)

// 响应拦截器
apiClient.interceptors.response.use(
  (response) => {
    console.log('收到响应:', response.status, response.config.url)
    return response
  },
  (error) => {
    console.error('响应错误:', error.response?.status, error.message)
    return Promise.reject(error)
  }
)

async function extractErrorMessage(error: any, fallback: string): Promise<string> {
  if (!error?.response) {
    return `${fallback}: 无法连接后端服务`
  }

  const data = error.response.data

  if (typeof data === 'string' && data.trim()) {
    return data
  }

  if (data instanceof Blob) {
    try {
      const text = (await data.text()).trim()
      if (!text) return fallback
      try {
        const parsed = JSON.parse(text)
        return parsed.detail || parsed.message || fallback
      } catch {
        return text
      }
    } catch {
      return fallback
    }
  }

  if (data?.detail) {
    return typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)
  }

  if (data?.message) {
    return data.message
  }

  return error.message || fallback
}

/**
 * 生成旅行计划
 */
export async function generateTripPlan(formData: TripFormData): Promise<TripPlanResponse> {
  try {
    const response = await apiClient.post<TripPlanResponse>('/api/trip/plan', formData)
    return response.data
  } catch (error: any) {
    console.error('生成旅行计划失败:', error)
    throw new Error(await extractErrorMessage(error, '生成旅行计划失败'))
  }
}

/**
 * 健康检查
 */
export async function healthCheck(): Promise<any> {
  try {
    const response = await apiClient.get('/api/trip/health')
    return response.data
  } catch (error: any) {
    console.error('健康检查失败:', error)
    throw new Error(await extractErrorMessage(error, '健康检查失败'))
  }
}

/**
 * 获取最新MAS运行轨迹图
 */
export async function getLatestTrace(): Promise<Blob> {
  try {
    const response = await apiClient.get('/api/mas/latest-trace', {
      responseType: 'blob'
    })
    if (!(response.data instanceof Blob)) {
      throw new Error('轨迹图响应格式错误')
    }
    if (response.data.type.includes('application/json')) {
      const text = await response.data.text()
      const parsed = JSON.parse(text)
      throw new Error(parsed.detail || parsed.message || '获取轨迹图失败')
    }
    return response.data
  } catch (error: any) {
    console.error('获取轨迹图失败:', error)
    throw new Error(await extractErrorMessage(error, '获取轨迹图失败'))
  }
}

export default apiClient
