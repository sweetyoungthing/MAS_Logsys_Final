import { reactive, readonly } from 'vue'
import type { TripPlan } from '@/types'

const STORAGE_KEY = 'trip-plan-store'

type TripPlanStoreState = {
  planId: string | null
  tripPlan: TripPlan | null
}

const state = reactive<TripPlanStoreState>({
  planId: null,
  tripPlan: null
})

function persistState() {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
}

function restoreState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return
    const parsed = JSON.parse(raw) as Partial<TripPlanStoreState>
    state.planId = parsed.planId ?? null
    state.tripPlan = parsed.tripPlan ?? null
  } catch (error) {
    console.error('恢复旅行计划缓存失败:', error)
  }
}

restoreState()

export function useTripPlanStore() {
  function setTripPlan(planId: string | null, tripPlan: TripPlan) {
    state.planId = planId
    state.tripPlan = tripPlan
    persistState()
  }

  function clearTripPlan() {
    state.planId = null
    state.tripPlan = null
    localStorage.removeItem(STORAGE_KEY)
  }

  return {
    state: readonly(state),
    setTripPlan,
    clearTripPlan
  }
}
