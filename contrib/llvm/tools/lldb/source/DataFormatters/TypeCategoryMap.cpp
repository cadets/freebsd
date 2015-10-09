//===-- TypeCategoryMap.cpp ----------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "lldb/DataFormatters/TypeCategoryMap.h"

#include "lldb/DataFormatters/FormatClasses.h"
#include "lldb/DataFormatters/FormatManager.h"

// C Includes
// C++ Includes
// Other libraries and framework includes
// Project includes

using namespace lldb;
using namespace lldb_private;

TypeCategoryMap::TypeCategoryMap (IFormatChangeListener* lst) :
m_map_mutex(Mutex::eMutexTypeRecursive),
listener(lst),
m_map(),
m_active_categories()
{
    ConstString default_cs("default");
    lldb::TypeCategoryImplSP default_sp = lldb::TypeCategoryImplSP(new TypeCategoryImpl(listener, default_cs));
    Add(default_cs,default_sp);
    Enable(default_cs,First);
}

void
TypeCategoryMap::Add (KeyType name, const ValueSP& entry)
{
    Mutex::Locker locker(m_map_mutex);
    m_map[name] = entry;
    if (listener)
        listener->Changed();
}

bool
TypeCategoryMap::Delete (KeyType name)
{
    Mutex::Locker locker(m_map_mutex);
    MapIterator iter = m_map.find(name);
    if (iter == m_map.end())
        return false;
    m_map.erase(name);
    Disable(name);
    if (listener)
        listener->Changed();
    return true;
}

bool
TypeCategoryMap::Enable (KeyType category_name, Position pos)
{
    Mutex::Locker locker(m_map_mutex);
    ValueSP category;
    if (!Get(category_name,category))
        return false;
    return Enable(category, pos);
}

bool
TypeCategoryMap::Disable (KeyType category_name)
{
    Mutex::Locker locker(m_map_mutex);
    ValueSP category;
    if (!Get(category_name,category))
        return false;
    return Disable(category);
}

bool
TypeCategoryMap::Enable (ValueSP category, Position pos)
{
    Mutex::Locker locker(m_map_mutex);
    if (category.get())
    {
        Position pos_w = pos;
        if (pos == First || m_active_categories.size() == 0)
            m_active_categories.push_front(category);
        else if (pos == Last || pos == m_active_categories.size())
            m_active_categories.push_back(category);
        else if (pos < m_active_categories.size())
        {
            ActiveCategoriesList::iterator iter = m_active_categories.begin();
            while (pos_w)
            {
                pos_w--,iter++;
            }
            m_active_categories.insert(iter,category);
        }
        else
            return false;
        category->Enable(true,
                         pos);
        return true;
    }
    return false;
}

bool
TypeCategoryMap::Disable (ValueSP category)
{
    Mutex::Locker locker(m_map_mutex);
    if (category.get())
    {
        m_active_categories.remove_if(delete_matching_categories(category));
        category->Disable();
        return true;
    }
    return false;
}

void
TypeCategoryMap::EnableAllCategories ()
{
    Mutex::Locker locker(m_map_mutex);
    std::vector<ValueSP> sorted_categories(m_map.size(), ValueSP());
    MapType::iterator iter = m_map.begin(), end = m_map.end();
    for (; iter != end; ++iter)
    {
        if (iter->second->IsEnabled())
            continue;
        auto pos = iter->second->GetLastEnabledPosition();
        if (pos >= sorted_categories.size())
        {
            auto iter = std::find_if(sorted_categories.begin(),
                                     sorted_categories.end(),
                                     [] (const ValueSP& sp) -> bool {
                                         return sp.get() == nullptr;
                                     });
            pos = std::distance(sorted_categories.begin(), iter);
        }
        sorted_categories.at(pos) = iter->second;
    }
    decltype(sorted_categories)::iterator viter = sorted_categories.begin(), vend = sorted_categories.end();
    for (; viter != vend; viter++)
        if (viter->get())
            Enable(*viter, Last);
}

void
TypeCategoryMap::DisableAllCategories ()
{
    Mutex::Locker locker(m_map_mutex);
    Position p = First;
    for (; false == m_active_categories.empty(); p++)
    {
        m_active_categories.front()->SetEnabledPosition(p);
        Disable(m_active_categories.front());
    }
}

void
TypeCategoryMap::Clear ()
{
    Mutex::Locker locker(m_map_mutex);
    m_map.clear();
    m_active_categories.clear();
    if (listener)
        listener->Changed();
}

bool
TypeCategoryMap::Get (KeyType name, ValueSP& entry)
{
    Mutex::Locker locker(m_map_mutex);
    MapIterator iter = m_map.find(name);
    if (iter == m_map.end())
        return false;
    entry = iter->second;
    return true;
}

bool
TypeCategoryMap::Get (uint32_t pos, ValueSP& entry)
{
    Mutex::Locker locker(m_map_mutex);
    MapIterator iter = m_map.begin();
    MapIterator end = m_map.end();
    while (pos > 0)
    {
        iter++;
        pos--;
        if (iter == end)
            return false;
    }
    entry = iter->second;
    return false;
}

bool
TypeCategoryMap::AnyMatches (ConstString type_name,
                             TypeCategoryImpl::FormatCategoryItems items,
                             bool only_enabled,
                             const char** matching_category,
                             TypeCategoryImpl::FormatCategoryItems* matching_type)
{
    Mutex::Locker locker(m_map_mutex);
    
    MapIterator pos, end = m_map.end();
    for (pos = m_map.begin(); pos != end; pos++)
    {
        if (pos->second->AnyMatches(type_name,
                                    items,
                                    only_enabled,
                                    matching_category,
                                    matching_type))
            return true;
    }
    return false;
}

lldb::TypeFormatImplSP
TypeCategoryMap::GetFormat (ValueObject& valobj,
                            lldb::DynamicValueType use_dynamic)
{
    Mutex::Locker locker(m_map_mutex);
    
    uint32_t reason_why;
    ActiveCategoriesIterator begin, end = m_active_categories.end();
    
    Log *log(lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_TYPES));
    
    FormattersMatchVector matches = FormatManager::GetPossibleMatches(valobj, use_dynamic);
    
    for (begin = m_active_categories.begin(); begin != end; begin++)
    {
        lldb::TypeCategoryImplSP category_sp = *begin;
        lldb::TypeFormatImplSP current_format;
        if (log)
            log->Printf("\n[TypeCategoryMap::GetFormat] Trying to use category %s", category_sp->GetName());
        if (!category_sp->Get(valobj, matches, current_format, &reason_why))
            continue;
        return current_format;
    }
    if (log)
        log->Printf("[TypeCategoryMap::GetFormat] nothing found - returning empty SP");
    return lldb::TypeFormatImplSP();
}

lldb::TypeSummaryImplSP
TypeCategoryMap::GetSummaryFormat (ValueObject& valobj,
                                   lldb::DynamicValueType use_dynamic)
{
    Mutex::Locker locker(m_map_mutex);
    
    uint32_t reason_why;
    ActiveCategoriesIterator begin, end = m_active_categories.end();
    
    Log *log(lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_TYPES));
    
    FormattersMatchVector matches = FormatManager::GetPossibleMatches(valobj, use_dynamic);
    
    for (begin = m_active_categories.begin(); begin != end; begin++)
    {
        lldb::TypeCategoryImplSP category_sp = *begin;
        lldb::TypeSummaryImplSP current_format;
        if (log)
            log->Printf("\n[CategoryMap::GetSummaryFormat] Trying to use category %s", category_sp->GetName());
        if (!category_sp->Get(valobj, matches, current_format, &reason_why))
            continue;
        return current_format;
    }
    if (log)
        log->Printf("[CategoryMap::GetSummaryFormat] nothing found - returning empty SP");
    return lldb::TypeSummaryImplSP();
}

#ifndef LLDB_DISABLE_PYTHON
lldb::SyntheticChildrenSP
TypeCategoryMap::GetSyntheticChildren (ValueObject& valobj,
                                       lldb::DynamicValueType use_dynamic)
{
    Mutex::Locker locker(m_map_mutex);
    
    uint32_t reason_why;
    
    ActiveCategoriesIterator begin, end = m_active_categories.end();
    
    Log *log(lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_TYPES));
    
    FormattersMatchVector matches = FormatManager::GetPossibleMatches(valobj, use_dynamic);
    
    for (begin = m_active_categories.begin(); begin != end; begin++)
    {
        lldb::TypeCategoryImplSP category_sp = *begin;
        lldb::SyntheticChildrenSP current_format;
        if (log)
            log->Printf("\n[CategoryMap::GetSyntheticChildren] Trying to use category %s", category_sp->GetName());
        if (!category_sp->Get(valobj, matches, current_format, &reason_why))
            continue;
        return current_format;
    }
    if (log)
        log->Printf("[CategoryMap::GetSyntheticChildren] nothing found - returning empty SP");
    return lldb::SyntheticChildrenSP();
}
#endif

lldb::TypeValidatorImplSP
TypeCategoryMap::GetValidator (ValueObject& valobj,
                               lldb::DynamicValueType use_dynamic)
{
    Mutex::Locker locker(m_map_mutex);
    
    uint32_t reason_why;
    ActiveCategoriesIterator begin, end = m_active_categories.end();
    
    Log *log(lldb_private::GetLogIfAllCategoriesSet (LIBLLDB_LOG_TYPES));
    
    FormattersMatchVector matches = FormatManager::GetPossibleMatches(valobj, use_dynamic);
    
    for (begin = m_active_categories.begin(); begin != end; begin++)
    {
        lldb::TypeCategoryImplSP category_sp = *begin;
        lldb::TypeValidatorImplSP current_format;
        if (log)
            log->Printf("\n[CategoryMap::GetValidator] Trying to use category %s", category_sp->GetName());
        if (!category_sp->Get(valobj, matches, current_format, &reason_why))
            continue;
        return current_format;
    }
    if (log)
        log->Printf("[CategoryMap::GetValidator] nothing found - returning empty SP");
    return lldb::TypeValidatorImplSP();
}

void
TypeCategoryMap::LoopThrough(CallbackType callback, void* param)
{
    if (callback)
    {
        Mutex::Locker locker(m_map_mutex);
        
        // loop through enabled categories in respective order
        {
            ActiveCategoriesIterator begin, end = m_active_categories.end();
            for (begin = m_active_categories.begin(); begin != end; begin++)
            {
                lldb::TypeCategoryImplSP category = *begin;
                ConstString type = ConstString(category->GetName());
                if (!callback(param, category))
                    break;
            }
        }
        
        // loop through disabled categories in just any order
        {
            MapIterator pos, end = m_map.end();
            for (pos = m_map.begin(); pos != end; pos++)
            {
                if (pos->second->IsEnabled())
                    continue;
                KeyType type = pos->first;
                if (!callback(param, pos->second))
                    break;
            }
        }
    }
}

TypeCategoryImplSP
TypeCategoryMap::GetAtIndex (uint32_t index)
{
    Mutex::Locker locker(m_map_mutex);
    
    if (index < m_map.size())
    {
        MapIterator pos, end = m_map.end();
        for (pos = m_map.begin(); pos != end; pos++)
        {
            if (index == 0)
                return pos->second;
            index--;
        }
    }
    
    return TypeCategoryImplSP();
}
