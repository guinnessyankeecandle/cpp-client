#pragma once
#include <string>
#include <vector>

class Group {
public:
    Group() = default;
    Group(int id, std::string name, int ownerId, std::vector<int> members, int epoch);

    int                     getId()      const;
    const std::string&      getName()    const;
    int                     getOwnerId() const;
    const std::vector<int>& getMembers() const;
    int                     getEpoch()   const;

    void addMember(int userId);
    void removeMember(int userId);
    void setEpoch(int epoch);

private:
    int              m_id{0};
    std::string      m_name;
    int              m_ownerId{0};
    std::vector<int> m_members;
    int              m_epoch{0};
};
