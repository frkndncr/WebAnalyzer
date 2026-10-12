import { createContext, useContext } from 'react';
import { DEFAULT_CATALOGUE } from '../lib/catalogue';

/** The module catalogue (live from the API once loaded, the bundled snapshot before that). */
export const CatalogueContext = createContext(DEFAULT_CATALOGUE);
export const useCatalogue = () => useContext(CatalogueContext);
