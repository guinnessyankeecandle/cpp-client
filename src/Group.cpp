#include "Group.hpp"
#include <algorithm>

Group::Group(int id, std::string name, int ownerId, std::vector<int> members, int epoch)
    : m_id(id), m_name(std::move(name)), m_ownerId(ownerId)
    , m_members(std::move(members)), m_epoch(epoch)
{}

int                     Group::getId()      const { return m_id; }
const std::string&      Group::getName()    const { return m_name; }
int                     Group::getOwnerId() const { return m_ownerId; }
const std::vector<int>& Group::getMembers() const { return m_members; }
int                     Group::getEpoch()   const { return m_epoch; }

void Group::addMember(int userId) {
    if (std::find(m_members.begin(), m_members.end(), userId) == m_members.end())
        m_members.push_back(userId);
}

void Group::removeMember(int userId) {
    m_members.erase(std::remove(m_members.begin(), m_members.end(), userId), m_members.end());
}

void Group::setEpoch(int epoch) { m_epoch = epoch; }
