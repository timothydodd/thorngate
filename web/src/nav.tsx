import { createContext, useContext } from 'react'
import type { RequestFilter } from './types'

// Nav lets any component open the IP panel, the ban dialog, or jump to the
// Requests tab with a filter, without threading callbacks through every level.
export interface Nav {
  openIP: (ip: string) => void
  searchRequests: (f: RequestFilter) => void
  // ban opens the ban dialog; onDone runs after a successful ban.
  ban: (ip: string, onDone?: () => void) => void
  archive: boolean // long history on disk: ranges past 24h are meaningful
}

export const NavContext = createContext<Nav>({
  openIP: () => {},
  searchRequests: () => {},
  ban: () => {},
  archive: false,
})

export const useNav = () => useContext(NavContext)
