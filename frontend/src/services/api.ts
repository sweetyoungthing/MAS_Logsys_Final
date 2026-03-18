import axios from 'axios'
import { message } from 'ant-design-vue'
import type { TripFormData, TripPlanResponse } from '@/types'
import type { TripPlan } from '@/types'

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '/').trim()
const SECURITY_ERROR_CODE = 'SECURITY_RISK_BLOCKED'

export class AppApiError extends Error {
  status?: number
  errorCode?: string
  riskLevel?: string
  riskScore?: number

  constructor(
    message: string,
    options: {
      status?: number
      errorCode?: string
      riskLevel?: string
      riskScore?: number
    } = {}
  ) {
    super(message)
    this.name = 'AppApiError'
    this.status = options.status
    this.errorCode = options.errorCode
    this.riskLevel = options.riskLevel
    this.riskScore = options.riskScore
  }
}

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
    const status = error.response?.status
    const data = error.response?.data ?? {}
    if (status === 403 && data?.error_code === SECURITY_ERROR_CODE) {
      const riskText = data?.risk_level ? `（风险等级: ${data.risk_level}）` : ''
      message.error(data?.message || `请求被安全策略拦截${riskText}`)
    }
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

function toAppApiError(error: any, fallback: string, messageText: string): AppApiError {
  const data = error?.response?.data ?? {}
  return new AppApiError(messageText || fallback, {
    status: error?.response?.status,
    errorCode: data?.error_code,
    riskLevel: data?.risk_level,
    riskScore: data?.risk_score
  })
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
    const messageText = await extractErrorMessage(error, '生成旅行计划失败')
    throw toAppApiError(error, '生成旅行计划失败', messageText)
  }
}

export async function fetchTripPlan(planId: string): Promise<TripPlanResponse> {
  try {
    const response = await apiClient.get<TripPlanResponse>(`/api/trip/plans/${planId}`)
    return response.data
  } catch (error: any) {
    console.error('获取旅行计划失败:', error)
    const messageText = await extractErrorMessage(error, '获取旅行计划失败')
    throw toAppApiError(error, '获取旅行计划失败', messageText)
  }
}

export async function updateTripPlan(planId: string, tripPlan: TripPlan): Promise<TripPlanResponse> {
  try {
    const response = await apiClient.put<TripPlanResponse>(`/api/trip/plans/${planId}`, tripPlan)
    return response.data
  } catch (error: any) {
    console.error('更新旅行计划失败:', error)
    const messageText = await extractErrorMessage(error, '更新旅行计划失败')
    throw toAppApiError(error, '更新旅行计划失败', messageText)
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
    const messageText = await extractErrorMessage(error, '健康检查失败')
    throw toAppApiError(error, '健康检查失败', messageText)
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
      throw new AppApiError(parsed.detail || parsed.message || '获取轨迹图失败')
    }
    return response.data
  } catch (error: any) {
    console.error('获取轨迹图失败:', error)
    const messageText = await extractErrorMessage(error, '获取轨迹图失败')
    throw toAppApiError(error, '获取轨迹图失败', messageText)
  }
}

export async function getAttractionPhoto(name: string): Promise<string | null> {
  try {
    const response = await apiClient.get('/api/poi/photo', {
      params: { name }
    })
    return response.data?.data?.photo_url ?? null
  } catch (error: any) {
    console.error('获取景点图片失败:', error)
    const messageText = await extractErrorMessage(error, '获取景点图片失败')
    throw toAppApiError(error, '获取景点图片失败', messageText)
  }
}

export default apiClient
