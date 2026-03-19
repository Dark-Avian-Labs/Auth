import { useState, type FormEvent } from 'react';

import { SEARCH_PLACEHOLDER } from '../../app/config';

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
        type="text"
        className="search-box w-52"
        aria-label="Search"
        placeholder={SEARCH_PLACEHOLDER}
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
      {query && (
        <button
          className="text-muted hover:text-foreground absolute top-1/2 right-2 -translate-y-1/2 text-lg"
          onClick={() => setQuery('')}
          aria-label="Clear search"
          type="button"
        >
          &times;
        </button>
      )}
    </form>
  );
}
