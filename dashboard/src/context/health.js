import { createContext, useContext } from 'react';

/** The latest /api/system-health payload (null until the first response). */
export const HealthContext = createContext(null);
export const useHealth = () => useContext(HealthContext);
