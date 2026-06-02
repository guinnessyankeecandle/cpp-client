module;
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
export module securemsg.models.group;

export class Group {
public:
  Group(const int32_t id, std::string name, std::vector<int32_t> members,
        const int32_t epoch)
      : group_id(id), group_name(std::move(name)),
        group_members(std::move(members)), group_epoch(epoch) {}

  [[nodiscard]] int32_t getId() const { return group_id; }
  [[nodiscard]] const std::string &getName() const { return group_name; }
  [[nodiscard]] const std::vector<int32_t> &getMembers() const {
    return group_members;
  }
  [[nodiscard]] int32_t getEpoch() const { return group_epoch; }

  void setEpoch(const int32_t epoch) { group_epoch = epoch; }

  void addMember(const int32_t userId) {
    if (std::ranges::find(group_members, userId) == group_members.end())
      group_members.push_back(userId);
  }

  void removeMember(const int32_t userId) { std::erase(group_members, userId); }

  [[nodiscard]] bool hasMember(const int32_t userId) const {
    return std::ranges::find(group_members, userId) != group_members.end();
  }

private:
  int32_t group_id;
  std::string group_name;
  std::vector<int32_t> group_members;
  int32_t group_epoch;
};
