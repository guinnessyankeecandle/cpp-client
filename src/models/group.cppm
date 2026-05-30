module;
#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>
export module securemsg.models.group;

export class Group {
public:
    Group() = default;
    Group(int32_t id, std::string name, int32_t ownerId,
          std::vector<int32_t> members, int32_t epoch)
        : m_id(id)
        , m_name(std::move(name))
        , m_ownerId(ownerId)
        , m_members(std::move(members))
        , m_epoch(epoch) {}

    int32_t                     getId()      const { return m_id; }
    const std::string&          getName()    const { return m_name; }
    int32_t                     getOwnerId() const { return m_ownerId; }
    const std::vector<int32_t>& getMembers() const { return m_members; }
    int32_t                     getEpoch()   const { return m_epoch; }

    void setEpoch(int32_t epoch) { m_epoch = epoch; }

    void addMember(int32_t userId) {
        if (std::find(m_members.begin(), m_members.end(), userId) == m_members.end())
            m_members.push_back(userId);
    }

    void removeMember(int32_t userId) {
        m_members.erase(std::remove(m_members.begin(), m_members.end(), userId),
                        m_members.end());
    }

    bool hasMember(int32_t userId) const {
        return std::find(m_members.begin(), m_members.end(), userId) != m_members.end();
    }

private:
    int32_t              m_id{0};
    std::string          m_name;
    int32_t              m_ownerId{0};
    std::vector<int32_t> m_members;
    int32_t              m_epoch{0};
};
