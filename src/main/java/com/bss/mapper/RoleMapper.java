package com.bss.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bss.entity.Role;
import java.util.List;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface RoleMapper extends BaseMapper<Role> {
  @Select({"select role_id from user_role where user_id=#{user_id}"})
  List<Integer> getList(@Param("user_id") Integer paramInteger);
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\mapper\RoleMapper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */