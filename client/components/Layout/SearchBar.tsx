import { useState, type FormEvent } from 'react';

import { SEARCH_PLACEHOLDER } from '../../app/config';
import { MaterialSymbol } from '../ui/MaterialSymbol';

interface SearchBarProps {
  onSearch?: (query: string) => void;
}

export function SearchBar({ onSearch }: SearchBarProps) {
  const [query, setQuery] = useState('');
  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!onSearch) {
      return;
    }
    onSearch(query);
  };

  return (
    <form className="search-wrapper relative" onSubmit={handleSubmit}>
      <input
        id="auth-header-search"
        name="search"
        type="text"
        role="searchbox"
        enterKeyHint="search"
        autoComplete="off"
        className="search-box w-52"
        aria-label="Search"
        placeholder={SEARCH_PLACEHOLDER}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {query && (
        <button
          className="text-muted hover:text-foreground absolute top-1/2 right-2 flex -translate-y-1/2 items-center justify-center p-0.5"
          onClick={() => setQuery('')}
          aria-label="Clear search"
          type="button"
        >
          <MaterialSymbol name="close" style={{ fontSize: 20 }} />
        </button>
      )}
    </form>
  );
}
