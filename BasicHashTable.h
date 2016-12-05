/**********
This library is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the
Free Software Foundation; either version 3 of the License, or (at your
option) any later version. (See <http://www.gnu.org/copyleft/lesser.html>.)

This library is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
more details.

You should have received a copy of the GNU Lesser General Public License
along with this library; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
**********/
// Copyright (c) 1996-2017 Live Networks, Inc.  All rights reserved.
// Basic Hash Table implementation
// C++ header

#ifndef _BASIC_HASH_TABLE_HH
#define _BASIC_HASH_TABLE_HH



// A simple hash table implementation, inspired by the hash table
// implementation used in Tcl 7.6: <http://www.tcl.tk/>

#define SMALL_HASH_TABLE_SIZE 4
class HashTable {
public:
  virtual ~HashTable();
  
  // The following must be implemented by a particular
  // implementation (subclass):
  static HashTable* create(int keyType);
  
  virtual void* Add(char const* key, void* value) = 0;
  // Returns the old value if different, otherwise 0
  virtual bool Remove(char const* key) = 0;
  virtual void* Lookup(char const* key) const = 0;
  // Returns 0 if not found
  virtual unsigned numEntries() const = 0;
  bool IsEmpty() const { return numEntries() == 0; }
  
  // Used to iterate through the members of the table:
  class Iterator {
  public:
    // The following must be implemented by a particular
    // implementation (subclass):
    static Iterator* create(HashTable const& hashTable);
    
    virtual ~Iterator();
    
    virtual void* next(char const*& key) = 0; // returns 0 if none
    
  protected:
    Iterator(); // abstract base class
  };
  
  // A shortcut that can be used to successively remove each of
  // the entries in the table (e.g., so that their values can be
  // deleted, if they happen to be pointers to allocated memory).
  void* RemoveNext();
  
  // Returns the first entry in the table.
  // (This is useful for deleting each entry in the table, if the entry's destructor also removes itself from the table.)
  void* getFirst();
  
protected:
  HashTable(); // abstract base class
};

// Warning: The following are deliberately the same as in
// Tcl's hash table implementation
int const STRING_HASH_KEYS = 0;
int const ONE_WORD_HASH_KEYS = 1;

class BasicHashTable: public HashTable {
private:
	class TableEntry; // forward

public:
  BasicHashTable(int keyType);
  virtual ~BasicHashTable();

  // Used to iterate through the members of the table:
  class Iterator; friend class Iterator; // to make Sun's C++ compiler happy
  class Iterator: public HashTable::Iterator {
  public:
    Iterator(BasicHashTable const& table);

  private: // implementation of inherited pure virtual functions
    void* next(char const*& key); // returns 0 if none

  private:
    BasicHashTable const& fTable;
    unsigned fNextIndex; // index of next bucket to be enumerated after this
    TableEntry* fNextEntry; // next entry in the current bucket
  };

public: // implementation of inherited pure virtual functions
  virtual void* Add(char const* key, void* value);
  // Returns the old value if different, otherwise 0
  virtual bool Remove(char const* key);
  virtual void* Lookup(char const* key) const;
  // Returns 0 if not found
  virtual unsigned numEntries() const;

private:
  class TableEntry {
  public:
    TableEntry* fNext;
    char const* key;
    void* value;
  };

  TableEntry* lookupKey(char const* key, unsigned& index) const;
    // returns entry matching "key", or NULL if none
  bool keyMatches(char const* key1, char const* key2) const;
    // used to implement "lookupKey()"

  TableEntry* insertNewEntry(unsigned index, char const* key);
    // creates a new entry, and inserts it in the table
  void assignKey(TableEntry* entry, char const* key);
    // used to implement "insertNewEntry()"

  void deleteEntry(unsigned index, TableEntry* entry);
  void deleteKey(TableEntry* entry);
    // used to implement "deleteEntry()"

  void rebuild(); // rebuilds the table as its size increases

  unsigned hashIndexFromKey(char const* key) const;
    // used to implement many of the routines above

  unsigned randomIndex(unsigned long i) const {
    return (unsigned)(((i*1103515245) >> fDownShift) & fMask);
  }

private:
  TableEntry** fBuckets; // pointer to bucket array
  TableEntry* fStaticBuckets[SMALL_HASH_TABLE_SIZE];// used for small tables
  unsigned fNumBuckets, fNumEntries, fRebuildSize, fDownShift, fMask;
  int fKeyType;
};

#endif
