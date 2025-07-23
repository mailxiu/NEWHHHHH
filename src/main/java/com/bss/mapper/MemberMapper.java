package com.bss.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.bss.entity.Member;
import com.bss.entity.MemberDTO;
import java.util.List;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

public interface MemberMapper extends BaseMapper<Member> {
  @Select({"select *,'indirect' AS relation FROM member where mid in (select uid FROM member where mid = ${uid})  and partner = ${partner} \nUNION ALL\nSELECT *,'direct' AS relation FROM member WHERE mid = ${uid} and partner = ${partner} ORDER BY create_time DESC LIMIT ${offset}, ${pageSize};"})
  List<MemberDTO> getInvitationMember(@Param("uid") Long paramLong, @Param("partner") Integer paramInteger1, @Param("offset") Integer paramInteger2, @Param("pageSize") Integer paramInteger3);
  
  @Select({"select *,'indirect' AS relation FROM member where mid in (select uid FROM member where mid = ${uid}) and partner = ${partner} \nUNION ALL\nSELECT *,'direct' AS relation FROM member WHERE mid = ${uid} and partner = ${partner}"})
  List<MemberDTO> getInvitationMemberCount(@Param("uid") Long paramLong, @Param("partner") Integer paramInteger);
}


/* Location:              C:\Users\yang\Documents\xwechat_files\wxid_3fhkjy8fz0wc11_2b47\msg\file\2025-07\recovery_applet-1.0.3-SNAPSHOT.jar!\BOOT-INF\classes\com\bss\mapper\MemberMapper.class
 * Java compiler version: 8 (52.0)
 * JD-Core Version:       1.1.3
 */